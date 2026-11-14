from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from ndr.contracts import ModelMetadata
from ndr.reporting.model_card import LIMITATION, write_model_card


def test_model_card_contains_metadata_and_limitation(tmp_path: Path) -> None:
    model_dir = tmp_path / "model"
    model_dir.mkdir()
    metadata = ModelMetadata(
        model_name="scan_lgbm",
        version="0.1.0",
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        stage="staging",
        feature_set_version="v0.4.0",
        features=["scan_unique_ports", "scan_rate"],
        threshold=0.42,
        normalization={},
        training={"train_runs": ["a", "b"], "train_windows": 12},
        metrics={"test_recall": 0.9, "test_fp_per_day": 2.0},
    )
    (model_dir / "metadata.json").write_text(
        metadata.model_dump_json(), encoding="utf-8"
    )
    out = tmp_path / "card.md"
    write_model_card(model_dir, out)
    text = out.read_text(encoding="utf-8")
    assert "scan_lgbm" in text
    assert "0.42" in text
    assert "test_recall" in text
    assert "train_runs: a, b" in text
    assert LIMITATION in text
