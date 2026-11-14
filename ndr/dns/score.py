"""Score DNS windows with the D7 LightGBM model."""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np

from ndr.anomaly.train import discover_runs
from ndr.beacon.model import shap_matrix, top_features
from ndr.contracts import DetectionEvent, ModelInfo, ModelMetadata, RuleInfo
from ndr.dns.train import LEXICAL_WEIGHT
from ndr.features.dns import (
    DNS_FEATURE_NAMES,
    DNS_FEATURE_SET_VERSION,
    build_dns_snapshots,
)
from ndr.features.dns_baseline import load_dns_profile
from ndr.zeek import iter_dns_jsonl


def score_dns(
    input_dir: Path, model_dir: Path, out_path: Path
) -> list[DetectionEvent]:
    metadata = ModelMetadata.model_validate_json(
        (model_dir / "metadata.json").read_text(encoding="utf-8")
    )
    if metadata.feature_set_version != DNS_FEATURE_SET_VERSION:
        raise ValueError(
            f"model feature_set_version {metadata.feature_set_version} "
            f"!= {DNS_FEATURE_SET_VERSION}"
        )
    if list(metadata.features) != list(DNS_FEATURE_NAMES):
        raise ValueError("model feature order does not match DNS_FEATURE_NAMES")

    baseline = load_dns_profile(model_dir / "dns_baseline.json")
    lgbm = joblib.load(model_dir / "lgbm.joblib")
    calibrator = joblib.load(model_dir / "calibrator.joblib")
    tunnel_index = DNS_FEATURE_NAMES.index("tunnel_score")

    events: list[DetectionEvent] = []
    for _, dns_path in discover_runs(input_dir, "dns.jsonl"):
        snapshots = build_dns_snapshots(
            list(iter_dns_jsonl(dns_path)), baseline
        )
        if not snapshots:
            continue
        matrix = np.asarray(
            [
                [snapshot.features[name] for name in DNS_FEATURE_NAMES]
                for snapshot in snapshots
            ],
            dtype=float,
        )
        calibrated = np.clip(
            calibrator.predict(lgbm.predict_proba(matrix)[:, 1]), 0.0, 1.0
        )
        scores = np.clip(
            (1.0 - LEXICAL_WEIGHT) * calibrated
            + LEXICAL_WEIGHT * matrix[:, tunnel_index],
            0.0,
            1.0,
        )
        contributions = shap_matrix(lgbm, matrix)

        for snapshot, score, row in zip(snapshots, scores, contributions):
            events.append(
                DetectionEvent(
                    timestamp=snapshot.window.end,
                    rule=RuleInfo(
                        id="NDR-ML-DNS-001",
                        name="ML DNS Tunneling",
                        version=metadata.version,
                    ),
                    model=ModelInfo(
                        name="dns_tunnel_lgbm",
                        version=metadata.version,
                        type="classification",
                    ),
                    score=float(score),
                    threshold=metadata.threshold,
                    is_alert=bool(score >= metadata.threshold),
                    top_features=top_features(
                        snapshot, baseline, row, DNS_FEATURE_NAMES
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
