"""Build the D1 anomaly report."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from ndr.anomaly.train import discover_runs
from ndr.contracts import DetectionEvent


def _load_detections(path: Path) -> list[DetectionEvent]:
    if not path.is_file():
        raise FileNotFoundError(path)
    detections: list[DetectionEvent] = []
    for lineno, line in enumerate(
        path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            detections.append(DetectionEvent.model_validate_json(line))
        except Exception as exc:
            raise ValueError(f"{path}:{lineno}: {exc}") from exc
    return detections


def build_report(
    detections_path: Path,
    input_dir: Path,
    out_path: Path,
    *,
    title: str = "D1 anomaly report (synthetic)",
    target_fp_per_day: float = 10.0,
) -> dict:
    detections = _load_detections(detections_path)
    runs = discover_runs(input_dir)

    rows: dict[tuple[str, str], dict[str, int]] = defaultdict(
        lambda: {"runs": 0, "windows": 0, "alerts": 0, "detected": 0}
    )
    run_summary: dict[str, dict] = {}
    benign_alerts = 0
    benign_hours = 0.0
    attack_runs = 0
    detected_attack_runs = 0

    for run, _ in runs:
        overlaps = [
            detection
            for detection in detections
            if detection.window.start < run.end_ts
            and detection.window.end > run.start_ts
        ]
        alerts = [detection for detection in overlaps if detection.is_alert]
        row = rows[(run.scenario, run.kind)]
        row["runs"] += 1
        row["windows"] += len(overlaps)
        row["alerts"] += len(alerts)

        if run.kind == "benign":
            benign_alerts += len(alerts)
            benign_hours += (run.end_ts - run.start_ts).total_seconds() / 3600.0
            detected = False
        else:
            attack_runs += 1
            detected = any(
                detection.entity.src_ip == run.attacker_ip for detection in alerts
            )
            if detected:
                detected_attack_runs += 1
                row["detected"] += 1

        run_summary[run.run_id] = {"detected": bool(detected), "alerts": len(alerts)}

    benign_fp_per_day = (
        benign_alerts / benign_hours * 24.0 if benign_hours > 0 else 0.0
    )
    attack_recall = (
        detected_attack_runs / attack_runs if attack_runs > 0 else 0.0
    )

    lines = [
        f"# {title}",
        "",
        "| scenario | kind | runs | scored_windows | alerts | detected | recall |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for scenario, kind in sorted(rows):
        row = rows[(scenario, kind)]
        if kind == "attack":
            detected_text = str(row["detected"])
            recall_text = f"{row['detected'] / row['runs']:.2f}"
        else:
            detected_text = "—"
            recall_text = "—"
        lines.append(
            f"| {scenario} | {kind} | {row['runs']} | {row['windows']} | "
            f"{row['alerts']} | {detected_text} | {recall_text} |"
        )

    lines.extend(
        [
            "",
            f"- Benign alerts: {benign_alerts} over {benign_hours:.2f} h → "
            f"{benign_fp_per_day:.2f} FP/day",
            f"- Attack runs detected: {detected_attack_runs}/{attack_runs} "
            f"(recall {attack_recall:.2f})",
            f"- Target FP/day: {target_fp_per_day:.1f} (threshold quantile stored in model metadata)",
            "- Synthetic data only: numbers validate wiring, not real-world detection.",
        ]
    )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    return {
        "benign_fp": benign_alerts,
        "benign_fp_per_day": benign_fp_per_day,
        "attack_recall": attack_recall,
        "runs": run_summary,
    }
