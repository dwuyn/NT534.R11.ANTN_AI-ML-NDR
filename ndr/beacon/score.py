"""Score snapshots with the D5 beaconing ensemble."""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np

from ndr.anomaly.train import discover_runs
from ndr.beacon.model import (
    anomaly_raw,
    normalize_anomaly,
    shap_matrix,
    top_features,
)
from ndr.contracts import (
    DetectionEvent,
    ModelInfo,
    ModelMetadata,
    RuleInfo,
)
from ndr.features.baseline import load_profile
from ndr.features.beacon import (
    BEACON_FEATURE_NAMES,
    BEACON_FEATURE_SET_VERSION,
    build_beacon_snapshots,
)
from ndr.zeek import iter_conn_jsonl


def score_beacon(
    input_dir: Path, model_dir: Path, out_path: Path
) -> list[DetectionEvent]:
    metadata = ModelMetadata.model_validate_json(
        (model_dir / "metadata.json").read_text(encoding="utf-8")
    )
    if metadata.feature_set_version != BEACON_FEATURE_SET_VERSION:
        raise ValueError(
            f"model feature_set_version {metadata.feature_set_version} "
            f"!= {BEACON_FEATURE_SET_VERSION}"
        )
    if list(metadata.features) != list(BEACON_FEATURE_NAMES):
        raise ValueError("model feature order does not match BEACON_FEATURE_NAMES")

    baseline = load_profile(model_dir / "baseline.json")
    lgbm = joblib.load(model_dir / "lgbm.joblib")
    calibrator = joblib.load(model_dir / "calibrator.joblib")
    iforest = joblib.load(model_dir / "iforest.joblib")
    low = float(metadata.normalization["lo"])
    high = float(metadata.normalization["hi"])

    events: list[DetectionEvent] = []
    for _, conn_path in discover_runs(input_dir):
        snapshots = build_beacon_snapshots(
            list(iter_conn_jsonl(conn_path)), baseline
        )
        if not snapshots:
            continue
        matrix = np.asarray(
            [
                [snapshot.features[name] for name in BEACON_FEATURE_NAMES]
                for snapshot in snapshots
            ],
            dtype=float,
        )
        calibrated = np.clip(
            calibrator.predict(lgbm.predict_proba(matrix)[:, 1]), 0.0, 1.0
        )
        anomaly = normalize_anomaly(anomaly_raw(iforest, matrix), low, high)
        scores = np.clip(0.7 * calibrated + 0.3 * anomaly, 0.0, 1.0)
        contributions = shap_matrix(lgbm, matrix)

        for snapshot, score, row in zip(snapshots, scores, contributions):
            top = top_features(
                snapshot, baseline, row, BEACON_FEATURE_NAMES
            )
            events.append(
                DetectionEvent(
                    timestamp=snapshot.window.end,
                    rule=RuleInfo(
                        id="NDR-ML-BEACON-001",
                        name="ML C2 Beaconing",
                        version=metadata.version,
                    ),
                    model=ModelInfo(
                        name="beaconing_lgbm_iforest",
                        version=metadata.version,
                        type="classification",
                    ),
                    score=float(score),
                    threshold=metadata.threshold,
                    is_alert=bool(score >= metadata.threshold),
                    top_features=top,
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
