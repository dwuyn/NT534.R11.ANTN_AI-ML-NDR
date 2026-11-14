"""Render a Markdown model card from model metadata."""

from __future__ import annotations

from pathlib import Path

from ndr.contracts import ModelMetadata

LIMITATION = "Synthetic data only; recalibrate thresholds on lab data before production."


def write_model_card(model_dir: Path, out_path: Path) -> None:
    metadata_path = model_dir / "metadata.json"
    if not metadata_path.is_file():
        raise FileNotFoundError(metadata_path)
    metadata = ModelMetadata.model_validate_json(
        metadata_path.read_text(encoding="utf-8")
    )

    lines = [
        f"# Model card: {metadata.model_name}",
        "",
        f"- Version: {metadata.version}",
        f"- Stage: {metadata.stage}",
        f"- Feature set: {metadata.feature_set_version}",
        f"- Threshold: {metadata.threshold:.6g}",
        f"- Owner: {metadata.owner}",
        "",
        "## Features",
        "",
        ", ".join(metadata.features),
        "",
        "## Training",
        "",
    ]
    for key, value in sorted(metadata.training.items()):
        if isinstance(value, (list, tuple)):
            value = ", ".join(str(item) for item in value)
        lines.append(f"- {key}: {value}")

    lines.extend(["", "## Metrics", "", "| metric | value |", "|---|---:|"])
    if metadata.metrics:
        for key, value in sorted(metadata.metrics.items()):
            lines.append(f"| {key} | {value:.6f} |")
    else:
        lines.append("| — | — |")

    lines.extend(["", "## Limitations", "", LIMITATION, ""])

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")
