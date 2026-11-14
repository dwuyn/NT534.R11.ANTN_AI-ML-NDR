"""Score lateral-movement windows with the D6 LightGBM model."""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np

from ndr.anomaly.train import discover_runs
from ndr.beacon.model import shap_matrix, top_features
from ndr.contracts import DetectionEvent, ModelInfo, ModelMetadata, RuleInfo
from ndr.features.lateral import (
    LATERAL_FEATURE_NAMES,
    LATERAL_FEATURE_SET_VERSION,
    build_lateral_snapshots,
    load_lateral_events,
    load_lateral_profile,
)


def score_lateral(
    input_dir: Path, model_dir: Path, out_path: Path
) -> list[DetectionEvent]:
    metadata = ModelMetadata.model_validate_json(
        (model_dir / "metadata.json").read_text(encoding="utf-8")
    )
    if metadata.feature_set_version != LATERAL_FEATURE_SET_VERSION:
        raise ValueError(
            f"model feature_set_version {metadata.feature_set_version} "
            f"!= {LATERAL_FEATURE_SET_VERSION}"
        )
    if list(metadata.features) != list(LATERAL_FEATURE_NAMES):
        raise ValueError(
            "model feature order does not match LATERAL_FEATURE_NAMES"
        )

    baseline = load_lateral_profile(model_dir / "lateral_baseline.json")
    lgbm = joblib.load(model_dir / "lgbm.joblib")
    calibrator = joblib.load(model_dir / "calibrator.joblib")

    events: list[DetectionEvent] = []
    for _, mapping_path in discover_runs(input_dir, "smb_mapping.jsonl"):
        snapshots = build_lateral_snapshots(
            load_lateral_events(mapping_path.parent), baseline
        )
        if not snapshots:
            continue
        matrix = np.asarray(
            [
                [snapshot.features[name] for name in LATERAL_FEATURE_NAMES]
                for snapshot in snapshots
            ],
            dtype=float,
        )
        scores = np.clip(
            calibrator.predict(lgbm.predict_proba(matrix)[:, 1]),
            0.0,
            1.0,
        )
        contributions = shap_matrix(lgbm, matrix)

        for snapshot, score, row in zip(snapshots, scores, contributions):
            events.append(
                DetectionEvent(
                    timestamp=snapshot.window.end,
                    rule=RuleInfo(
                        id="NDR-ML-LATERAL-001",
                        name="ML Lateral Movement",
                        version=metadata.version,
                    ),
                    model=ModelInfo(
                        name="lateral_lgbm",
                        version=metadata.version,
                        type="classification",
                    ),
                    score=float(score),
                    threshold=metadata.threshold,
                    is_alert=bool(score >= metadata.threshold),
                    top_features=top_features(
                        snapshot, baseline, row, LATERAL_FEATURE_NAMES
                    ),
                    entity=snapshot.entity,
                    window=snapshot.window,
                    uids=list(snapshot.context.get("uids", [])),
                    snapshot_id=snapshot.snapshot_id,
                )
            )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(event.model_dump_json() + "\n")
    return events
