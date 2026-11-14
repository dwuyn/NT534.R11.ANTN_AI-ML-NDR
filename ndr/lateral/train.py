"""Train the D6 LightGBM lateral-movement model."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from lightgbm import LGBMClassifier
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import average_precision_score, precision_score, recall_score

from ndr.anomaly.train import discover_runs
from ndr.contracts import GroundTruthRun, ModelMetadata
from ndr.features.calibration import ensure_above_benign
from ndr.features.lateral import (
    LATERAL_FEATURE_NAMES,
    LATERAL_FEATURE_SET_VERSION,
    LATERAL_MIN_EVENTS,
    LATERAL_WINDOW_SECONDS,
    build_lateral_snapshots,
    build_raw_lateral_profile,
    finalize_lateral_profile,
    load_lateral_events,
    save_lateral_profile,
)

LATERAL_MODEL_VERSION = "0.1.0"
TARGET_FP_PER_DAY = 10.0


def _matrix(snapshots: list) -> np.ndarray:
    return np.asarray(
        [
            [snapshot.features[name] for name in LATERAL_FEATURE_NAMES]
            for snapshot in snapshots
        ],
        dtype=float,
    )


def _labels(snapshots: list) -> np.ndarray:
    return np.asarray([snapshot.label for snapshot in snapshots], dtype=int)


def _snapshots_for_run(
    run: GroundTruthRun, run_dir: Path, baseline
) -> list:
    snapshots = build_lateral_snapshots(
        load_lateral_events(run_dir), baseline
    )
    for snapshot in snapshots:
        snapshot.label = (
            1
            if run.kind == "attack"
            and snapshot.entity.src_ip == run.attacker_ip
            else 0
        )
    return snapshots


def train_lateral(
    input_dir: Path,
    out_dir: Path,
    seed: int = 42,
    target_fp_per_day: float = TARGET_FP_PER_DAY,
) -> ModelMetadata:
    runs = discover_runs(input_dir, "smb_mapping.jsonl")
    benign = [(run, path) for run, path in runs if run.kind == "benign"]
    attacks = [(run, path) for run, path in runs if run.kind == "attack"]
    if len(benign) < 6 or len(attacks) < 5:
        raise ValueError(
            "lateral corpus needs >=6 benign and >=5 attack runs, got "
            f"{len(benign)} benign and {len(attacks)} attack"
        )

    benign_train = benign[:3]
    benign_val = benign[3:5]
    benign_test = benign[5:]
    attack_train = attacks[:3]
    attack_val = attacks[3:4]
    attack_test = attacks[4:]

    train_runs = benign_train + attack_train
    val_runs = benign_val + attack_val
    test_runs = benign_test + attack_test

    benign_events = []
    for _, mapping_path in benign_train:
        benign_events.extend(load_lateral_events(mapping_path.parent))
    baseline = build_raw_lateral_profile(benign_events)
    baseline.feature_set_version = LATERAL_FEATURE_SET_VERSION

    train_snapshots = []
    for run, mapping_path in train_runs:
        train_snapshots.extend(
            _snapshots_for_run(run, mapping_path.parent, baseline)
        )
    baseline = finalize_lateral_profile(baseline, train_snapshots)

    val_snapshots = []
    for run, mapping_path in val_runs:
        val_snapshots.extend(
            _snapshots_for_run(run, mapping_path.parent, baseline)
        )
    test_snapshots = []
    for run, mapping_path in test_runs:
        test_snapshots.extend(
            _snapshots_for_run(run, mapping_path.parent, baseline)
        )

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

    def scores(matrix: np.ndarray) -> np.ndarray:
        return np.clip(
            calibrator.predict(lgbm.predict_proba(matrix)[:, 1]),
            0.0,
            1.0,
        )

    val_scores = scores(x_val)
    test_scores = scores(x_test)

    n_entities = len(
        {snapshot.entity.src_ip for snapshot in train_snapshots}
    )
    windows_per_day = (86400.0 / LATERAL_WINDOW_SECONDS) * max(
        1, n_entities
    )
    quantile = 1.0 - target_fp_per_day / windows_per_day
    if not 0.0 < quantile < 1.0:
        raise ValueError(
            f"invalid threshold quantile {quantile}; check target_fp_per_day"
        )
    val_benign_scores = val_scores[y_val == 0]
    if len(val_benign_scores) == 0:
        raise ValueError("validation has no benign windows")
    threshold = ensure_above_benign(
        float(np.quantile(val_benign_scores, quantile)),
        val_benign_scores,
    )

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
        model_name="lateral_lgbm",
        version=LATERAL_MODEL_VERSION,
        created_at=datetime.now(timezone.utc),
        stage="staging",
        feature_set_version=LATERAL_FEATURE_SET_VERSION,
        features=list(LATERAL_FEATURE_NAMES),
        threshold=threshold,
        normalization={},
        training={
            "train_runs": [run.run_id for run, _ in train_runs],
            "val_runs": [run.run_id for run, _ in val_runs],
            "test_runs": [run.run_id for run, _ in test_runs],
            "train_windows": len(train_snapshots),
            "positive_windows": int(np.sum(y_train)),
            "negative_windows": int(np.sum(y_train == 0)),
            "window_seconds": LATERAL_WINDOW_SECONDS,
            "min_events": LATERAL_MIN_EVENTS,
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
    save_lateral_profile(baseline, out_dir / "lateral_baseline.json")
    (out_dir / "metadata.json").write_text(
        metadata.model_dump_json(indent=2), encoding="utf-8"
    )
    return metadata
