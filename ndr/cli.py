"""Command-line entry points for the NDR ML foundation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ndr.anomaly.report import build_report
from ndr.anomaly.score import score
from ndr.anomaly.train import train
from ndr.beacon.score import score_beacon
from ndr.beacon.train import train_beacon
from ndr.dns.score import score_dns
from ndr.dns.train import train_dns
from ndr.synth.beacon import generate_beacon_corpus
from ndr.synth.dns import generate_dns_corpus
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


def _cmd_beacon_synth(args: argparse.Namespace) -> int:
    runs = generate_beacon_corpus(
        out_dir=Path(args.out),
        seed=args.seed,
        benign_runs=args.benign_runs,
        attack_runs=args.attack_runs,
    )
    print(f"generated {len(runs)} beacon runs in {args.out}")
    return 0


def _cmd_beacon_train(args: argparse.Namespace) -> int:
    metadata = train_beacon(
        input_dir=Path(args.input),
        out_dir=Path(args.out),
        seed=args.seed,
        target_fp_per_day=args.target_fp_per_day,
    )
    print(f"trained {metadata.model_name} {metadata.version} in {args.out}")
    print(f"threshold={metadata.threshold:.6f} windows={metadata.training['train_windows']}")
    print(json.dumps(metadata.metrics, indent=2))
    return 0


def _cmd_beacon_score(args: argparse.Namespace) -> int:
    events = score_beacon(
        input_dir=Path(args.input),
        model_dir=Path(args.model),
        out_path=Path(args.out),
    )
    alerts = sum(1 for event in events if event.is_alert)
    print(f"wrote {len(events)} detections ({alerts} alerts) to {args.out}")
    return 0


def _cmd_beacon_report(args: argparse.Namespace) -> int:
    summary = build_report(
        detections_path=Path(args.detections),
        input_dir=Path(args.input),
        out_path=Path(args.out),
        title="D5 beaconing report (synthetic)",
        target_fp_per_day=args.target_fp_per_day,
    )
    print(json.dumps(summary, indent=2))
    return 0


def _cmd_beacon_demo(args: argparse.Namespace) -> int:
    workdir = Path(args.workdir)
    synthetic = workdir / "synthetic"
    model = workdir / "model"
    detections = workdir / "detections.jsonl"
    report = workdir / "report.md"

    generate_beacon_corpus(out_dir=synthetic, seed=args.seed)
    train_beacon(input_dir=synthetic, out_dir=model, seed=args.seed)
    score_beacon(input_dir=synthetic, model_dir=model, out_path=detections)
    summary = build_report(
        detections_path=detections,
        input_dir=synthetic,
        out_path=report,
        title="D5 beaconing report (synthetic)",
        target_fp_per_day=10.0,
    )
    print(json.dumps(summary, indent=2))
    return 0


def _cmd_dns_synth(args: argparse.Namespace) -> int:
    runs = generate_dns_corpus(
        out_dir=Path(args.out),
        seed=args.seed,
        benign_runs=args.benign_runs,
        attack_runs=args.attack_runs,
    )
    print(f"generated {len(runs)} dns runs in {args.out}")
    return 0


def _cmd_dns_train(args: argparse.Namespace) -> int:
    metadata = train_dns(
        input_dir=Path(args.input),
        out_dir=Path(args.out),
        seed=args.seed,
        target_fp_per_day=args.target_fp_per_day,
    )
    print(f"trained {metadata.model_name} {metadata.version} in {args.out}")
    print(
        f"threshold={metadata.threshold:.6f} "
        f"windows={metadata.training['train_windows']}"
    )
    print(json.dumps(metadata.metrics, indent=2))
    return 0


def _cmd_dns_score(args: argparse.Namespace) -> int:
    events = score_dns(
        input_dir=Path(args.input),
        model_dir=Path(args.model),
        out_path=Path(args.out),
    )
    alerts = sum(1 for event in events if event.is_alert)
    print(f"wrote {len(events)} detections ({alerts} alerts) to {args.out}")
    return 0


def _cmd_dns_report(args: argparse.Namespace) -> int:
    summary = build_report(
        detections_path=Path(args.detections),
        input_dir=Path(args.input),
        out_path=Path(args.out),
        title="D7 DNS tunneling report (synthetic)",
        target_fp_per_day=args.target_fp_per_day,
        run_filename="dns.jsonl",
    )
    print(json.dumps(summary, indent=2))
    return 0


def _cmd_dns_demo(args: argparse.Namespace) -> int:
    workdir = Path(args.workdir)
    synthetic = workdir / "synthetic"
    model = workdir / "model"
    detections = workdir / "detections.jsonl"
    report = workdir / "report.md"

    generate_dns_corpus(out_dir=synthetic, seed=args.seed)
    train_dns(input_dir=synthetic, out_dir=model, seed=args.seed)
    score_dns(input_dir=synthetic, model_dir=model, out_path=detections)
    summary = build_report(
        detections_path=detections,
        input_dir=synthetic,
        out_path=report,
        title="D7 DNS tunneling report (synthetic)",
        target_fp_per_day=10.0,
        run_filename="dns.jsonl",
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

    beacon_synth = subparsers.add_parser(
        "beacon-synth", help="generate the synthetic D5 beacon corpus"
    )
    beacon_synth.add_argument("--out", default="data/beacon-synth")
    beacon_synth.add_argument("--seed", type=int, default=42)
    beacon_synth.add_argument("--benign-runs", type=int, default=6)
    beacon_synth.add_argument("--attack-runs", type=int, default=6)
    beacon_synth.set_defaults(func=_cmd_beacon_synth)

    beacon_train = subparsers.add_parser(
        "beacon-train", help="train the D5 beaconing ensemble"
    )
    beacon_train.add_argument("--input", default="data/beacon-synth")
    beacon_train.add_argument("--out", default="data/model/beacon")
    beacon_train.add_argument("--seed", type=int, default=42)
    beacon_train.add_argument("--target-fp-per-day", type=float, default=10.0)
    beacon_train.set_defaults(func=_cmd_beacon_train)

    beacon_score = subparsers.add_parser(
        "beacon-score", help="score snapshots with the D5 model"
    )
    beacon_score.add_argument("--input", default="data/beacon-synth")
    beacon_score.add_argument("--model", default="data/model/beacon")
    beacon_score.add_argument("--out", default="data/detections/beacon.jsonl")
    beacon_score.set_defaults(func=_cmd_beacon_score)

    beacon_report = subparsers.add_parser(
        "beacon-report", help="build the D5 metric report"
    )
    beacon_report.add_argument(
        "--detections", default="data/detections/beacon.jsonl"
    )
    beacon_report.add_argument("--input", default="data/beacon-synth")
    beacon_report.add_argument("--out", default="data/reports/beacon.md")
    beacon_report.add_argument("--target-fp-per-day", type=float, default=10.0)
    beacon_report.set_defaults(func=_cmd_beacon_report)

    beacon_demo = subparsers.add_parser(
        "beacon-demo", help="run the full synthetic D5 pipeline"
    )
    beacon_demo.add_argument("--workdir", default="data/beacon-demo")
    beacon_demo.add_argument("--seed", type=int, default=42)
    beacon_demo.set_defaults(func=_cmd_beacon_demo)

    dns_synth = subparsers.add_parser(
        "dns-synth", help="generate the synthetic D7 DNS corpus"
    )
    dns_synth.add_argument("--out", default="data/dns-synth")
    dns_synth.add_argument("--seed", type=int, default=42)
    dns_synth.add_argument("--benign-runs", type=int, default=6)
    dns_synth.add_argument("--attack-runs", type=int, default=6)
    dns_synth.set_defaults(func=_cmd_dns_synth)

    dns_train = subparsers.add_parser(
        "dns-train", help="train the D7 DNS tunneling model"
    )
    dns_train.add_argument("--input", default="data/dns-synth")
    dns_train.add_argument("--out", default="data/model/dns")
    dns_train.add_argument("--seed", type=int, default=42)
    dns_train.add_argument("--target-fp-per-day", type=float, default=10.0)
    dns_train.set_defaults(func=_cmd_dns_train)

    dns_score = subparsers.add_parser(
        "dns-score", help="score DNS windows with the D7 model"
    )
    dns_score.add_argument("--input", default="data/dns-synth")
    dns_score.add_argument("--model", default="data/model/dns")
    dns_score.add_argument("--out", default="data/detections/dns.jsonl")
    dns_score.set_defaults(func=_cmd_dns_score)

    dns_report = subparsers.add_parser(
        "dns-report", help="build the D7 metric report"
    )
    dns_report.add_argument("--detections", default="data/detections/dns.jsonl")
    dns_report.add_argument("--input", default="data/dns-synth")
    dns_report.add_argument("--out", default="data/reports/dns.md")
    dns_report.add_argument("--target-fp-per-day", type=float, default=10.0)
    dns_report.set_defaults(func=_cmd_dns_report)

    dns_demo = subparsers.add_parser(
        "dns-demo", help="run the full synthetic D7 pipeline"
    )
    dns_demo.add_argument("--workdir", default="data/dns-demo")
    dns_demo.add_argument("--seed", type=int, default=42)
    dns_demo.set_defaults(func=_cmd_dns_demo)

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
