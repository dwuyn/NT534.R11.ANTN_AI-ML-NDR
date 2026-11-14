"""Train the D1 Isolation Forest on benign windows."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import RobustScaler

from ndr.contracts import GroundTruthRun, ModelMetadata
from ndr.features.baseline import (
    build_raw_profile,
    finalize_profile,
    save_profile,
)
from ndr.features.conn import FEATURE_NAMES, FEATURE_SET_VERSION, build_snapshots
from ndr.features.windows import WINDOW_SECONDS
from ndr.zeek import iter_conn_jsonl

MODEL_VERSION = "0.1.0"
TARGET_FP_PER_DAY = 10.0


def discover_runs(input_dir: Path) -> list[tuple[GroundTruthRun, Path]]:
    paths = sorted(input_dir.glob("*/run.json"))
    if not paths:
        raise ValueError(f"no run.json under {input_dir}")
    discovered: list[tuple[GroundTruthRun, Path]] = []
    for path in paths:
        try:
            run = GroundTruthRun.model_validate_json(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ValueError(f"{path}: {exc}") from exc
        conn_path = path.parent / "conn.jsonl"
        if not conn_path.is_file():
            raise FileNotFoundError(conn_path)
        discovered.append((run, conn_path))
    return discovered


def train(
    input_dir: Path,
    out_dir: Path,
    contamination: float = 0.01,
    seed: int = 42,
    target_fp_per_day: float = TARGET_FP_PER_DAY,
) -> ModelMetadata:
    runs = discover_runs(input_dir)
    benign_runs = [(run, path) for run, path in runs if run.kind == "benign"]
    if not benign_runs:
        raise ValueError("no benign runs found for training")

    records = []
    for _, conn_path in benign_runs:
        records.extend(iter_conn_jsonl(conn_path))
    if not records:
        raise ValueError("benign runs contain no connection records")

    profile = build_raw_profile(records)
    snapshots = build_snapshots(records, profile)
    if len(snapshots) < 100:
        raise ValueError(f"need >= 100 benign windows, got {len(snapshots)}")

    profile = finalize_profile(profile, snapshots)
    matrix = np.asarray(
        [[snapshot.features[name] for name in FEATURE_NAMES] for snapshot in snapshots],
        dtype=float,
    )

    pipeline = Pipeline(
        steps=[
            ("scaler", RobustScaler()),
            (
                "iforest",
                IsolationForest(
                    n_estimators=200,
                    max_samples="auto",
                    contamination=contamination,
                    random_state=seed,
                    n_jobs=-1,
                ),
            ),
        ]
    )
    pipeline.fit(matrix)

    raw = -pipeline.decision_function(matrix)
    low = float(np.percentile(raw, 1))
    high = float(np.percentile(raw, 99.9))
    if high <= low:
        high = low + 1.0
    scores = np.clip((raw - low) / (high - low), 0.0, 1.0)

    n_hosts = len({record.orig_h for record in records})
    windows_per_day = (86400.0 / WINDOW_SECONDS) * max(1, n_hosts)
    quantile = 1.0 - target_fp_per_day / windows_per_day
    if not 0.0 < quantile < 1.0:
        raise ValueError(
            f"invalid threshold quantile {quantile}; check target_fp_per_day"
        )
    threshold = float(np.quantile(scores, quantile))

    metadata = ModelMetadata(
        model_name="anomaly_iforest",
        version=MODEL_VERSION,
        created_at=datetime.now(timezone.utc),
        stage="staging",
        feature_set_version=FEATURE_SET_VERSION,
        features=list(FEATURE_NAMES),
        threshold=threshold,
        normalization={"lo": low, "hi": high},
        training={
            "runs": [run.run_id for run, _ in benign_runs],
            "windows": len(snapshots),
            "contamination": contamination,
            "seed": seed,
            "window_seconds": WINDOW_SECONDS,
            "n_hosts": n_hosts,
            "target_fp_per_day": target_fp_per_day,
            "threshold_quantile": quantile,
        },
        metrics={"train_alert_rate": float(np.mean(scores >= threshold))},
        owner="team-ndr",
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, out_dir / "model.joblib")
    save_profile(profile, out_dir / "baseline.json")
    (out_dir / "metadata.json").write_text(
        metadata.model_dump_json(indent=2), encoding="utf-8"
    )
    return metadata
