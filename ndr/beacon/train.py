"""Train the D5 LightGBM + Isolation Forest beaconing ensemble."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from lightgbm import LGBMClassifier
from sklearn.ensemble import IsolationForest
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import average_precision_score, precision_score, recall_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import RobustScaler

from ndr.anomaly.train import discover_runs
from ndr.beacon.model import anomaly_raw, normalize_anomaly
from ndr.contracts import GroundTruthRun, ModelMetadata
from ndr.features.baseline import (
    build_raw_profile,
    finalize_profile,
    save_profile,
)
from ndr.features.beacon import (
    BEACON_FEATURE_NAMES,
    BEACON_FEATURE_SET_VERSION,
    build_beacon_snapshots,
)
from ndr.features.windows import (
    BEACON_MIN_EVENTS,
    BEACON_WINDOW_SECONDS,
)
from ndr.zeek import iter_conn_jsonl

BEACON_MODEL_VERSION = "0.1.0"
TARGET_FP_PER_DAY = 10.0
ENSEMBLE_WEIGHTS = {"supervised": 0.7, "anomaly": 0.3}


def _matrix(snapshots: list) -> np.ndarray:
    return np.asarray(
        [
            [snapshot.features[name] for name in BEACON_FEATURE_NAMES]
            for snapshot in snapshots
        ],
        dtype=float,
    )


def _labels(snapshots: list) -> np.ndarray:
    return np.asarray([snapshot.label for snapshot in snapshots], dtype=int)


def _snapshots_for_run(
    run: GroundTruthRun, conn_path: Path, baseline
) -> list:
    snapshots = build_beacon_snapshots(
        list(iter_conn_jsonl(conn_path)), baseline
    )
    for snapshot in snapshots:
        snapshot.label = (
            1
            if run.kind == "attack"
            and snapshot.entity.src_ip == run.attacker_ip
            else 0
        )
    return snapshots


def train_beacon(
    input_dir: Path,
    out_dir: Path,
    seed: int = 42,
    target_fp_per_day: float = TARGET_FP_PER_DAY,
) -> ModelMetadata:
    runs = discover_runs(input_dir)
    benign = [(run, path) for run, path in runs if run.kind == "benign"]
    attacks = [(run, path) for run, path in runs if run.kind == "attack"]
    if len(benign) < 6 or len(attacks) < 5:
        raise ValueError(
            "beacon corpus needs >=6 benign and >=5 attack runs, got "
            f"{len(benign)} benign and {len(attacks)} attack"
        )

    benign_train = benign[:4]
    benign_val = benign[4:5]
    benign_test = benign[5:]
    attack_train = attacks[:3]
    attack_val = attacks[3:4]
    attack_test = attacks[4:]

    train_runs = benign_train + attack_train
    val_runs = benign_val + attack_val
    test_runs = benign_test + attack_test

    benign_records = []
    for _, conn_path in benign_train:
        benign_records.extend(iter_conn_jsonl(conn_path))
    profile = build_raw_profile(benign_records)
    profile.feature_set_version = BEACON_FEATURE_SET_VERSION

    train_snapshots = []
    for run, conn_path in train_runs:
        train_snapshots.extend(_snapshots_for_run(run, conn_path, profile))
    profile = finalize_profile(profile, train_snapshots)

    val_snapshots = []
    for run, conn_path in val_runs:
        val_snapshots.extend(_snapshots_for_run(run, conn_path, profile))
    test_snapshots = []
    for run, conn_path in test_runs:
        test_snapshots.extend(_snapshots_for_run(run, conn_path, profile))

    x_train, y_train = _matrix(train_snapshots), _labels(train_snapshots)
    x_val, y_val = _matrix(val_snapshots), _labels(val_snapshots)
    x_test, y_test = _matrix(test_snapshots), _labels(test_snapshots)

    if set(y_train) != {0, 1}:
        raise ValueError("training data must contain both classes")
    if set(y_val) != {0, 1}:
        raise ValueError("validation must contain both classes")
    if set(y_test) != {0, 1}:
        raise ValueError("test must contain both classes")

    lgbm_params = {
        "n_estimators": 300,
        "learning_rate": 0.05,
        "num_leaves": 31,
        "min_child_samples": 10,
        "subsample": 0.9,
        "colsample_bytree": 0.9,
        "class_weight": "balanced",
        "random_state": seed,
        "n_jobs": -1,
        "verbose": -1,
    }
    lgbm = LGBMClassifier(**lgbm_params)
    lgbm.fit(x_train, y_train)

    val_proba = lgbm.predict_proba(x_val)[:, 1]
    calibrator = IsotonicRegression(out_of_bounds="clip").fit(val_proba, y_val)

    iforest = Pipeline(
        steps=[
            ("scaler", RobustScaler()),
            (
                "iforest",
                IsolationForest(
                    n_estimators=200,
                    max_samples="auto",
                    contamination=0.01,
                    random_state=seed,
                    n_jobs=-1,
                ),
            ),
        ]
    )
    benign_train = x_train[y_train == 0]
    iforest.fit(benign_train)

    raw_train = anomaly_raw(iforest, benign_train)
    low = float(np.percentile(raw_train, 1))
    high = float(np.percentile(raw_train, 99.9))
    if high <= low:
        high = low + 1.0

    def scores(matrix: np.ndarray) -> np.ndarray:
        calibrated = np.clip(
            calibrator.predict(lgbm.predict_proba(matrix)[:, 1]), 0.0, 1.0
        )
        anomaly = normalize_anomaly(anomaly_raw(iforest, matrix), low, high)
        return np.clip(
            ENSEMBLE_WEIGHTS["supervised"] * calibrated
            + ENSEMBLE_WEIGHTS["anomaly"] * anomaly,
            0.0,
            1.0,
        )

    val_scores = scores(x_val)
    test_scores = scores(x_test)

    n_entities = len(
        {
            (
                snapshot.entity.src_ip,
                snapshot.entity.dst_ip,
                snapshot.entity.dst_port,
                snapshot.entity.proto,
            )
            for snapshot in train_snapshots
        }
    )
    windows_per_day = (
        86400.0 / BEACON_WINDOW_SECONDS
    ) * max(1, n_entities)
    quantile = 1.0 - target_fp_per_day / windows_per_day
    if not 0.0 < quantile < 1.0:
        raise ValueError(
            f"invalid threshold quantile {quantile}; check target_fp_per_day"
        )
    val_benign_scores = val_scores[y_val == 0]
    if len(val_benign_scores) == 0:
        raise ValueError("validation has no benign windows")
    threshold = float(np.quantile(val_benign_scores, quantile))

    test_fp = int(np.sum((test_scores >= threshold) & (y_test == 0)))
    test_negatives = int(np.sum(y_test == 0))
    metrics = {
        "val_pr_auc": float(average_precision_score(y_val, val_scores)),
        "val_recall": float(
            recall_score(
                y_val, (val_scores >= threshold).astype(int), zero_division=0
            )
        ),
        "val_precision": float(
            precision_score(
                y_val, (val_scores >= threshold).astype(int), zero_division=0
            )
        ),
        "test_pr_auc": float(average_precision_score(y_test, test_scores)),
        "test_recall": float(
            recall_score(
                y_test, (test_scores >= threshold).astype(int), zero_division=0
            )
        ),
        "test_precision": float(
            precision_score(
                y_test, (test_scores >= threshold).astype(int), zero_division=0
            )
        ),
        "test_fp_per_day": float(
            test_fp / max(1, test_negatives) * windows_per_day
        ),
    }

    metadata = ModelMetadata(
        model_name="beaconing_lgbm_iforest",
        version=BEACON_MODEL_VERSION,
        created_at=datetime.now(timezone.utc),
        stage="staging",
        feature_set_version=BEACON_FEATURE_SET_VERSION,
        features=list(BEACON_FEATURE_NAMES),
        threshold=threshold,
        normalization={"lo": low, "hi": high},
        training={
            "train_runs": [run.run_id for run, _ in train_runs],
            "val_runs": [run.run_id for run, _ in val_runs],
            "test_runs": [run.run_id for run, _ in test_runs],
            "train_windows": len(train_snapshots),
            "positive_windows": int(np.sum(y_train)),
            "negative_windows": int(np.sum(y_train == 0)),
            "window_seconds": BEACON_WINDOW_SECONDS,
            "min_events": BEACON_MIN_EVENTS,
            "ensemble_weights": ENSEMBLE_WEIGHTS,
            "calibration": "isotonic",
            "target_fp_per_day": target_fp_per_day,
            "threshold_quantile": quantile,
            "n_entities": n_entities,
            "seed": seed,
            "lgbm_params": lgbm_params,
        },
        metrics=metrics,
        owner="team-ndr",
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(lgbm, out_dir / "lgbm.joblib")
    joblib.dump(calibrator, out_dir / "calibrator.joblib")
    joblib.dump(iforest, out_dir / "iforest.joblib")
    save_profile(profile, out_dir / "baseline.json")
    (out_dir / "metadata.json").write_text(
        metadata.model_dump_json(indent=2), encoding="utf-8"
    )
    return metadata
