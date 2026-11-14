"""Score feature snapshots with the trained D1 model."""

from __future__ import annotations

from pathlib import Path
from typing import Sequence

import joblib
import numpy as np

from ndr.anomaly.train import discover_runs
from ndr.contracts import (
    DetectionEvent,
    ModelInfo,
    ModelMetadata,
    RuleInfo,
    TopFeature,
)
from ndr.features.baseline import BaselineProfile, load_profile
from ndr.features.conn import FEATURE_NAMES, FEATURE_SET_VERSION, build_snapshots
from ndr.zeek import iter_conn_jsonl


def _normalized_scores(
    snapshots: Sequence, pipeline, metadata: ModelMetadata
) -> np.ndarray:
    matrix = np.asarray(
        [
            [snapshot.features[name] for name in metadata.features]
            for snapshot in snapshots
        ],
        dtype=float,
    )
    raw = -pipeline.decision_function(matrix)
    low = float(metadata.normalization["lo"])
    high = float(metadata.normalization["hi"])
    if high <= low:
        high = low + 1.0
    return np.clip((raw - low) / (high - low), 0.0, 1.0)


def score_snapshots(
    snapshots: Sequence,
    pipeline,
    metadata: ModelMetadata,
    baseline: BaselineProfile,
) -> list[DetectionEvent]:
    if not snapshots:
        return []

    scores = _normalized_scores(snapshots, pipeline, metadata)
    events: list[DetectionEvent] = []
    for snapshot, raw_score in zip(snapshots, scores):
        score = float(raw_score)
        top = sorted(
            (
                TopFeature(
                    name=name,
                    value=float(snapshot.features[name]),
                    z=float(
                        (
                            snapshot.features[name]
                            - baseline.feature_mean.get(name, 0.0)
                        )
                        / (baseline.feature_std.get(name, 1.0) or 1.0)
                    ),
                )
                for name in FEATURE_NAMES
            ),
            key=lambda feature: abs(feature.z),
            reverse=True,
        )[:3]
        events.append(
            DetectionEvent(
                timestamp=snapshot.window.end,
                rule=RuleInfo(
                    id="NDR-ML-ANOM-001",
                    name="ML Anomaly (conn)",
                    version=metadata.version,
                ),
                model=ModelInfo(
                    name="anomaly_iforest",
                    version=metadata.version,
                    type="anomaly",
                ),
                score=score,
                threshold=metadata.threshold,
                is_alert=bool(score >= metadata.threshold),
                top_features=top,
                entity=snapshot.entity,
                window=snapshot.window,
                uids=list(snapshot.context.get("uids", [])),
                snapshot_id=snapshot.snapshot_id,
            )
        )
    return events


def score(input_dir: Path, model_dir: Path, out_path: Path) -> list[DetectionEvent]:
    metadata = ModelMetadata.model_validate_json(
        (model_dir / "metadata.json").read_text(encoding="utf-8")
    )
    if metadata.feature_set_version != FEATURE_SET_VERSION:
        raise ValueError(
            f"model feature_set_version {metadata.feature_set_version} "
            f"!= {FEATURE_SET_VERSION}"
        )
    if list(metadata.features) != list(FEATURE_NAMES):
        raise ValueError("model feature order does not match FEATURE_NAMES")

    baseline = load_profile(model_dir / "baseline.json")
    pipeline = joblib.load(model_dir / "model.joblib")

    events: list[DetectionEvent] = []
    for _, conn_path in discover_runs(input_dir):
        records = list(iter_conn_jsonl(conn_path))
        snapshots = build_snapshots(records, baseline)
        events.extend(score_snapshots(snapshots, pipeline, metadata, baseline))

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(event.model_dump_json() + "\n")
    return events
