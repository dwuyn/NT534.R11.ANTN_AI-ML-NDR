"""Command-line entry points for the NDR ML foundation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ndr.anomaly.report import build_report
from ndr.anomaly.score import score
from ndr.anomaly.train import train
from ndr.synth.generate import generate


def _cmd_synth(args: argparse.Namespace) -> int:
    runs = generate(
        out_dir=Path(args.out),
        seed=args.seed,
        benign_runs=args.benign_runs,
        attack_runs=args.attack_runs,
        benign_minutes=args.benign_minutes,
    )
    print(f"generated {len(runs)} runs in {args.out}")
    return 0


def _cmd_train(args: argparse.Namespace) -> int:
    metadata = train(
        input_dir=Path(args.input),
        out_dir=Path(args.out),
        contamination=args.contamination,
        seed=args.seed,
        target_fp_per_day=args.target_fp_per_day,
    )
    print(f"trained {metadata.model_name} {metadata.version} in {args.out}")
    print(f"threshold={metadata.threshold:.6f} windows={metadata.training['windows']}")
    return 0


def _cmd_score(args: argparse.Namespace) -> int:
    events = score(
        input_dir=Path(args.input),
        model_dir=Path(args.model),
        out_path=Path(args.out),
    )
    alerts = sum(1 for event in events if event.is_alert)
    print(f"wrote {len(events)} detections ({alerts} alerts) to {args.out}")
    return 0


def _cmd_report(args: argparse.Namespace) -> int:
    summary = build_report(
        detections_path=Path(args.detections),
        input_dir=Path(args.input),
        out_path=Path(args.out),
    )
    print(json.dumps(summary, indent=2))
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    workdir = Path(args.workdir)
    synthetic = workdir / "synthetic"
    model = workdir / "model"
    detections = workdir / "detections.jsonl"
    report = workdir / "report.md"

    generate(
        out_dir=synthetic,
        seed=args.seed,
        benign_runs=args.benign_runs,
        attack_runs=args.attack_runs,
        benign_minutes=args.benign_minutes,
    )
    train(input_dir=synthetic, out_dir=model, seed=args.seed)
    score(input_dir=synthetic, model_dir=model, out_path=detections)
    summary = build_report(
        detections_path=detections, input_dir=synthetic, out_path=report
    )
    print(json.dumps(summary, indent=2))
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ndr")
    subparsers = parser.add_subparsers(dest="command", required=True)

    synth = subparsers.add_parser("synth", help="generate synthetic Zeek conn logs")
    synth.add_argument("--out", default="data/synthetic")
    synth.add_argument("--seed", type=int, default=42)
    synth.add_argument("--benign-runs", type=int, default=4)
    synth.add_argument("--attack-runs", type=int, default=4)
    synth.add_argument("--benign-minutes", type=int, default=60)
    synth.set_defaults(func=_cmd_synth)

    train_parser = subparsers.add_parser("train", help="train the D1 Isolation Forest")
    train_parser.add_argument("--input", default="data/synthetic")
    train_parser.add_argument("--out", default="data/model/anomaly")
    train_parser.add_argument("--contamination", type=float, default=0.01)
    train_parser.add_argument("--seed", type=int, default=42)
    train_parser.add_argument("--target-fp-per-day", type=float, default=10.0)
    train_parser.set_defaults(func=_cmd_train)

    score_parser = subparsers.add_parser("score", help="score snapshots")
    score_parser.add_argument("--input", default="data/synthetic")
    score_parser.add_argument("--model", default="data/model/anomaly")
    score_parser.add_argument("--out", default="data/detections/detections.jsonl")
    score_parser.set_defaults(func=_cmd_score)

    report_parser = subparsers.add_parser("report", help="build the metric report")
    report_parser.add_argument("--detections", default="data/detections/detections.jsonl")
    report_parser.add_argument("--input", default="data/synthetic")
    report_parser.add_argument("--out", default="data/reports/anomaly.md")
    report_parser.set_defaults(func=_cmd_report)

    demo = subparsers.add_parser("demo", help="run the full synthetic pipeline")
    demo.add_argument("--workdir", default="data/demo")
    demo.add_argument("--seed", type=int, default=42)
    demo.add_argument("--benign-runs", type=int, default=4)
    demo.add_argument("--attack-runs", type=int, default=4)
    demo.add_argument("--benign-minutes", type=int, default=60)
    demo.set_defaults(func=_cmd_demo)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except (ValueError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
