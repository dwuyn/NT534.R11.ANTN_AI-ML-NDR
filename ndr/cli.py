"""Command-line entry points for the NDR ML foundation."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

from ndr.anomaly.report import build_report
from ndr.anomaly.score import score
from ndr.anomaly.train import train
from ndr.beacon.score import score_beacon
from ndr.beacon.train import train_beacon
from ndr.brute.score import score_brute
from ndr.brute.train import train_brute
from ndr.dns.score import score_dns
from ndr.dns.train import train_dns
from ndr.llm.eval import build_eval_alerts, evaluate_triage
from ndr.llm.provider import MockProvider
from ndr.llm.triage import triage_alerts
from ndr.lateral.score import score_lateral
from ndr.lateral.train import train_lateral
from ndr.malware.score import score_malware
from ndr.malware.train import train_malware
from ndr.prelab import run_prelab
from ndr.reporting.model_card import write_model_card
from ndr.response.engine import ResponseSimulator, decide_response
from ndr.response.policy import ResponsePolicy, load_allowlist
from ndr.risk.engine import (
    build_alerts,
    demo_enrichment,
    load_alerts,
    load_detections,
    load_enrichment,
    write_alerts,
)
from ndr.risk.report import build_risk_report
from ndr.scan.score import score_scan
from ndr.scan.train import train_scan
from ndr.synth.beacon import generate_beacon_corpus
from ndr.synth.brute import generate_brute_corpus
from ndr.synth.dns import generate_dns_corpus
from ndr.synth.generate import generate
from ndr.synth.lateral import generate_lateral_corpus
from ndr.synth.malware import generate_malware_corpus
from ndr.synth.scan import generate_scan_corpus


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


def _cmd_risk_build(args: argparse.Namespace) -> int:
    enrichment = (
        load_enrichment(Path(args.enrichment)) if args.enrichment else {}
    )
    detections = load_detections(Path(args.input))
    alerts = build_alerts(detections, enrichment)
    write_alerts(alerts, Path(args.out))
    print(f"wrote {len(alerts)} alerts to {args.out}")
    return 0


def _cmd_risk_report(args: argparse.Namespace) -> int:
    summary = build_risk_report(
        alerts_path=Path(args.alerts),
        input_dir=Path(args.input),
        out_path=Path(args.out),
    )
    print(json.dumps(summary, indent=2))
    return 0


def _cmd_risk_demo(args: argparse.Namespace) -> int:
    workdir = Path(args.workdir)
    detections_dir = workdir / "detections"

    generate(
        out_dir=workdir / "d1" / "synthetic",
        seed=args.seed,
        benign_runs=4,
        attack_runs=4,
        benign_minutes=60,
    )
    train(
        input_dir=workdir / "d1" / "synthetic",
        out_dir=workdir / "d1" / "model",
        seed=args.seed,
    )
    score(
        input_dir=workdir / "d1" / "synthetic",
        model_dir=workdir / "d1" / "model",
        out_path=detections_dir / "anomaly.jsonl",
    )

    generate_beacon_corpus(
        out_dir=workdir / "d5" / "synthetic", seed=args.seed
    )
    train_beacon(
        input_dir=workdir / "d5" / "synthetic",
        out_dir=workdir / "d5" / "model",
        seed=args.seed,
    )
    score_beacon(
        input_dir=workdir / "d5" / "synthetic",
        model_dir=workdir / "d5" / "model",
        out_path=detections_dir / "beacon.jsonl",
    )

    generate_dns_corpus(out_dir=workdir / "d7" / "synthetic", seed=args.seed)
    train_dns(
        input_dir=workdir / "d7" / "synthetic",
        out_dir=workdir / "d7" / "model",
        seed=args.seed,
    )
    score_dns(
        input_dir=workdir / "d7" / "synthetic",
        model_dir=workdir / "d7" / "model",
        out_path=detections_dir / "dns.jsonl",
    )

    enrichment = demo_enrichment()
    (workdir / "enrichment.json").write_text(
        json.dumps(
            {
                address: profile.model_dump()
                for address, profile in sorted(enrichment.items())
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    alerts = build_alerts(load_detections(detections_dir), enrichment)
    write_alerts(alerts, workdir / "alerts.jsonl")
    summary = build_risk_report(
        alerts_path=workdir / "alerts.jsonl",
        input_dir=detections_dir,
        out_path=workdir / "report.md",
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


def _cmd_llm_triage(args: argparse.Namespace) -> int:
    alerts = load_alerts(Path(args.alerts))
    results = triage_alerts(
        alerts,
        MockProvider(),
        audit_path=Path(args.audit),
    )
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        for result in results:
            handle.write(result.model_dump_json() + "\n")
    print(f"wrote {len(results)} triage results to {args.out}")
    return 0


def _cmd_llm_eval(args: argparse.Namespace) -> int:
    summary = evaluate_triage(build_eval_alerts(), MockProvider())
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def _cmd_response_sim(args: argparse.Namespace) -> int:
    alerts = load_alerts(Path(args.alerts))
    policy = ResponsePolicy(allowlist=load_allowlist(Path(args.allowlist)))
    simulator = ResponseSimulator()
    decisions = []
    recent: list[datetime] = []
    for alert in alerts:
        timestamp = alert.first_seen or alert.timestamp
        recent = [
            moment
            for moment in recent
            if 0.0 <= (timestamp - moment).total_seconds() < 60.0
        ]
        decision = decide_response(alert, policy, len(recent))
        if decision.allowed:
            recent.append(timestamp)
            simulator.apply(decision, timestamp)
        decisions.append(decision)

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as handle:
        for decision in decisions:
            handle.write(json.dumps(asdict(decision), sort_keys=True) + "\n")
    simulator.write_jsonl(Path(args.audit))
    print(
        f"wrote {len(decisions)} decisions "
        f"({sum(1 for decision in decisions if decision.allowed)} allowed) to {args.out}"
    )
    return 0


def _cmd_model_card(args: argparse.Namespace) -> int:
    write_model_card(Path(args.model), Path(args.out))
    print(f"wrote model card to {args.out}")
    return 0


def _cmd_prelab_demo(args: argparse.Namespace) -> int:
    summary = run_prelab(Path(args.workdir), seed=args.seed)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


def _add_detector_commands(
    subparsers,
    *,
    prefix: str,
    synth_default: str,
    model_default: str,
    detection_default: str,
    report_default: str,
    title: str,
    run_filename: str,
    generate_fn,
    train_fn,
    score_fn,
) -> None:
    synth = subparsers.add_parser(
        f"{prefix}-synth", help=f"generate the synthetic {prefix} corpus"
    )
    synth.add_argument("--out", default=synth_default)
    synth.add_argument("--seed", type=int, default=42)
    synth.add_argument("--benign-runs", type=int, default=6)
    synth.add_argument("--attack-runs", type=int, default=6)

    def run_synth(args: argparse.Namespace) -> int:
        runs = generate_fn(
            out_dir=Path(args.out),
            seed=args.seed,
            benign_runs=args.benign_runs,
            attack_runs=args.attack_runs,
        )
        print(f"generated {len(runs)} {prefix} runs in {args.out}")
        return 0

    synth.set_defaults(func=run_synth)

    train_parser = subparsers.add_parser(
        f"{prefix}-train", help=f"train the {prefix} model"
    )
    train_parser.add_argument("--input", default=synth_default)
    train_parser.add_argument("--out", default=model_default)
    train_parser.add_argument("--seed", type=int, default=42)
    train_parser.add_argument("--target-fp-per-day", type=float, default=10.0)

    def run_train(args: argparse.Namespace) -> int:
        metadata = train_fn(
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

    train_parser.set_defaults(func=run_train)

    score_parser = subparsers.add_parser(
        f"{prefix}-score", help=f"score snapshots with the {prefix} model"
    )
    score_parser.add_argument("--input", default=synth_default)
    score_parser.add_argument("--model", default=model_default)
    score_parser.add_argument("--out", default=detection_default)

    def run_score(args: argparse.Namespace) -> int:
        events = score_fn(
            input_dir=Path(args.input),
            model_dir=Path(args.model),
            out_path=Path(args.out),
        )
        alerts = sum(1 for event in events if event.is_alert)
        print(f"wrote {len(events)} detections ({alerts} alerts) to {args.out}")
        return 0

    score_parser.set_defaults(func=run_score)

    report_parser = subparsers.add_parser(
        f"{prefix}-report", help=f"build the {prefix} metric report"
    )
    report_parser.add_argument("--detections", default=detection_default)
    report_parser.add_argument("--input", default=synth_default)
    report_parser.add_argument("--out", default=report_default)
    report_parser.add_argument("--target-fp-per-day", type=float, default=10.0)

    def run_report(args: argparse.Namespace) -> int:
        summary = build_report(
            detections_path=Path(args.detections),
            input_dir=Path(args.input),
            out_path=Path(args.out),
            title=title,
            target_fp_per_day=args.target_fp_per_day,
            run_filename=run_filename,
        )
        print(json.dumps(summary, indent=2))
        return 0

    report_parser.set_defaults(func=run_report)

    demo = subparsers.add_parser(
        f"{prefix}-demo", help=f"run the full synthetic {prefix} pipeline"
    )
    demo.add_argument("--workdir", default=f"data/{prefix}-demo")
    demo.add_argument("--seed", type=int, default=42)

    def run_demo(args: argparse.Namespace) -> int:
        workdir = Path(args.workdir)
        synthetic = workdir / "synthetic"
        model = workdir / "model"
        detections = workdir / f"{prefix}.jsonl"
        report = workdir / "report.md"
        generate_fn(out_dir=synthetic, seed=args.seed)
        train_fn(input_dir=synthetic, out_dir=model, seed=args.seed)
        score_fn(input_dir=synthetic, model_dir=model, out_path=detections)
        summary = build_report(
            detections_path=detections,
            input_dir=synthetic,
            out_path=report,
            title=title,
            target_fp_per_day=10.0,
            run_filename=run_filename,
        )
        print(json.dumps(summary, indent=2))
        return 0

    demo.set_defaults(func=run_demo)


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

    risk_build = subparsers.add_parser(
        "risk-build", help="deduplicate detections and build risk alerts"
    )
    risk_build.add_argument("--input", default="data/detections")
    risk_build.add_argument("--out", default="data/alerts/alerts.jsonl")
    risk_build.add_argument("--enrichment", default=None)
    risk_build.set_defaults(func=_cmd_risk_build)

    risk_report = subparsers.add_parser(
        "risk-report", help="build the D8 risk fusion report"
    )
    risk_report.add_argument("--alerts", default="data/alerts/alerts.jsonl")
    risk_report.add_argument("--input", default="data/detections")
    risk_report.add_argument("--out", default="data/reports/risk.md")
    risk_report.set_defaults(func=_cmd_risk_report)

    risk_demo = subparsers.add_parser(
        "risk-demo", help="run the full synthetic D8 pipeline"
    )
    risk_demo.add_argument("--workdir", default="data/risk-demo")
    risk_demo.add_argument("--seed", type=int, default=42)
    risk_demo.set_defaults(func=_cmd_risk_demo)

    _add_detector_commands(
        subparsers,
        prefix="scan",
        synth_default="data/scan-synth",
        model_default="data/model/scan",
        detection_default="data/detections/scan.jsonl",
        report_default="data/reports/scan.md",
        title="D2 scan report (synthetic)",
        run_filename="conn.jsonl",
        generate_fn=generate_scan_corpus,
        train_fn=train_scan,
        score_fn=score_scan,
    )
    _add_detector_commands(
        subparsers,
        prefix="brute",
        synth_default="data/brute-synth",
        model_default="data/model/brute",
        detection_default="data/detections/brute.jsonl",
        report_default="data/reports/brute.md",
        title="D3 brute force report (synthetic)",
        run_filename="ssh.jsonl",
        generate_fn=generate_brute_corpus,
        train_fn=train_brute,
        score_fn=score_brute,
    )
    _add_detector_commands(
        subparsers,
        prefix="malware",
        synth_default="data/malware-synth",
        model_default="data/model/malware",
        detection_default="data/detections/malware.jsonl",
        report_default="data/reports/malware.md",
        title="D4 malware download report (synthetic)",
        run_filename="http.jsonl",
        generate_fn=generate_malware_corpus,
        train_fn=train_malware,
        score_fn=score_malware,
    )
    _add_detector_commands(
        subparsers,
        prefix="lateral",
        synth_default="data/lateral-synth",
        model_default="data/model/lateral",
        detection_default="data/detections/lateral.jsonl",
        report_default="data/reports/lateral.md",
        title="D6 lateral movement report (synthetic)",
        run_filename="smb_mapping.jsonl",
        generate_fn=generate_lateral_corpus,
        train_fn=train_lateral,
        score_fn=score_lateral,
    )

    llm_triage = subparsers.add_parser(
        "llm-triage", help="triage high/critical alerts with the mock LLM"
    )
    llm_triage.add_argument("--alerts", default="data/alerts/alerts.jsonl")
    llm_triage.add_argument("--out", default="data/triage/triage.jsonl")
    llm_triage.add_argument("--audit", default="data/audit/llm.jsonl")
    llm_triage.set_defaults(func=_cmd_llm_triage)

    llm_eval = subparsers.add_parser(
        "llm-eval", help="evaluate the mock LLM triage harness"
    )
    llm_eval.add_argument("--out", default="data/reports/llm-eval.json")
    llm_eval.set_defaults(func=_cmd_llm_eval)

    response_sim = subparsers.add_parser(
        "response-sim", help="simulate response policy decisions"
    )
    response_sim.add_argument("--alerts", default="data/alerts/alerts.jsonl")
    response_sim.add_argument("--out", default="data/response/decisions.jsonl")
    response_sim.add_argument("--audit", default="data/audit/response.jsonl")
    response_sim.add_argument("--allowlist", default="data/response-allowlist.json")
    response_sim.set_defaults(func=_cmd_response_sim)

    model_card = subparsers.add_parser(
        "model-card", help="render a Markdown model card"
    )
    model_card.add_argument("--model", default="data/model/scan")
    model_card.add_argument("--out", default="data/reports/scan-card.md")
    model_card.set_defaults(func=_cmd_model_card)

    prelab = subparsers.add_parser(
        "prelab-demo", help="run the full synthetic pre-lab pipeline"
    )
    prelab.add_argument("--workdir", default="data/prelab")
    prelab.add_argument("--seed", type=int, default=42)
    prelab.set_defaults(func=_cmd_prelab_demo)

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
