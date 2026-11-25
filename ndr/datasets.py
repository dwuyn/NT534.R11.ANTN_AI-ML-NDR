"""Build detector training corpora from public datasets."""

from __future__ import annotations

import csv
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
from collections import Counter, defaultdict
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

from ndr.anomaly.train import train
from ndr.beacon.train import train_beacon
from ndr.brute.train import train_brute
from ndr.contracts import GroundTruthRun
from ndr.dns.train import train_dns
from ndr.lab import prepare_lab_runs
from ndr.lateral.train import train_lateral
from ndr.malware.train import train_malware
from ndr.scan.train import train_scan
from ndr.synth.lateral import generate_lateral_corpus
from ndr.zeek import iter_conn_jsonl, iter_dns_jsonl, iter_files_jsonl, iter_http_jsonl

DETECTORS = ("D1", "D2", "D3", "D4", "D5", "D6", "D7")
DETECTOR_DIRS = {
    "D1": "d1",
    "D2": "d2",
    "D3": "d3",
    "D4": "d4",
    "D5": "d5",
    "D6": "d6",
    "D7": "d7",
}
CIC_TS_FORMATS = (
    "%d/%m/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
)
MTA_EXECUTABLE_EXTENSIONS = {
    "exe",
    "dll",
    "ps1",
    "bat",
    "js",
    "vbs",
    "scr",
    "zip",
    "rar",
    "7z",
    "tar",
    "gz",
}
UWF_REQUIRED_COLUMNS = {
    "ts",
    "uid",
    "src_ip_zeek",
    "src_port_zeek",
    "dest_ip_zeek",
    "dest_port_zeek",
    "proto",
    "label_binary",
}
RUN_ID_RE = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass(frozen=True)
class UwfData:
    raw_root: Path
    benign_runs: list[GroundTruthRun]
    attack_runs: list[GroundTruthRun]


@dataclass(frozen=True)
class CicData:
    tuesday_raw: Path
    friday_raw: Path
    monday_raw: Path | None
    labels: list[dict]
    tuesday_bounds: tuple[float, float]
    friday_bounds: tuple[float, float]
    monday_bounds: tuple[float, float] | None
    temp_paths: tuple[Path, ...]


def _ensure_empty(path: Path, label: str) -> None:
    if path.exists():
        if not path.is_dir():
            raise ValueError(f"{path}: {label} must be a directory")
        if next(path.iterdir(), None) is not None:
            raise ValueError(f"{path}: {label} must be empty")


def _utc(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=UTC)


def _safe_id(text: str) -> str:
    return RUN_ID_RE.sub("_", text).strip("_") or "run"


def _optional(value: str | None) -> str | None:
    if value is None:
        return None
    text = value.strip()
    return text or None


def _int(value: str | None, where: str, name: str, default: int = 0) -> int:
    if value is None or not value.strip():
        return default
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{where}: invalid {name}: {value!r}") from exc


def _float(value: str | None, where: str, name: str) -> float:
    if value is None or not value.strip():
        raise ValueError(f"{where}: missing {name}")
    try:
        return float(value)
    except ValueError as exc:
        raise ValueError(f"{where}: invalid {name}: {value!r}") from exc


def _parse_ts(value: str, where: str) -> float:
    text = value.strip()
    for fmt in CIC_TS_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        # CIC-IDS-2017 TrafficLabelling uses a 12-hour clock without AM/PM
        # and New Brunswick local time (UTC-3 during the July capture).
        if parsed.hour < 8:
            parsed += timedelta(hours=12)
        return parsed.replace(tzinfo=timezone(timedelta(hours=-3))).timestamp()
    raise ValueError(f"{where}: invalid timestamp: {value!r}")


def _write_conn_record(handle, obj: dict) -> None:
    handle.write(json.dumps(obj, sort_keys=True) + "\n")


def _uwf_conn_rows(csv_paths: Sequence[Path]) -> Iterator[dict]:
    for path in csv_paths:
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None:
                raise ValueError(f"{path}: missing CSV header")
            headers = {name.strip() for name in reader.fieldnames}
            missing = UWF_REQUIRED_COLUMNS - headers
            if missing:
                raise ValueError(
                    f"{path}: missing columns {', '.join(sorted(missing))}"
                )
            for lineno, raw in enumerate(reader, start=2):
                row = {str(key).strip(): value for key, value in raw.items()}
                where = f"{path}:{lineno}"
                src = row.get("src_ip_zeek", "")
                dst = row.get("dest_ip_zeek", "")
                uid = row.get("uid", "")
                if not src or not dst or not uid:
                    raise ValueError(f"{where}: missing source, destination, or uid")
                timestamp = _float(row.get("ts"), where, "ts")
                obj = {
                    "ts": timestamp,
                    "uid": uid,
                    "id": {
                        "orig_h": src,
                        "orig_p": _int(
                            row.get("src_port_zeek"), where, "src_port_zeek"
                        ),
                        "resp_h": dst,
                        "resp_p": _int(
                            row.get("dest_port_zeek"), where, "dest_port_zeek"
                        ),
                    },
                    "proto": row.get("proto") or "tcp",
                    "service": _optional(row.get("service")),
                    "duration": (
                        float(row["duration"])
                        if row.get("duration", "").strip()
                        else None
                    ),
                    "orig_bytes": _int(row.get("orig_bytes"), where, "orig_bytes"),
                    "resp_bytes": _int(row.get("resp_bytes"), where, "resp_bytes"),
                    "orig_pkts": _int(row.get("orig_pkts"), where, "orig_pkts"),
                    "resp_pkts": _int(row.get("resp_pkts"), where, "resp_pkts"),
                    "conn_state": _optional(row.get("conn_state")),
                    "history": _optional(row.get("history")),
                    "community_id": _optional(row.get("community_id")),
                }
                yield {
                    "obj": obj,
                    "ts": timestamp,
                    "src": src,
                    "dst": dst,
                    "uid": uid,
                    "tactic": (row.get("label_tactic") or "").strip().lower(),
                    "technique": (row.get("label_technique") or "").strip(),
                    "binary": (row.get("label_binary") or "").strip().lower(),
                }


def _prepare_uwf(root: Path) -> UwfData:
    root = Path(root).resolve()
    benign_csvs = sorted((root / "uwf" / "Benign").glob("*.csv"))
    recon_csvs = sorted((root / "uwf" / "Reconnaissance").glob("*.csv"))
    if not benign_csvs or not recon_csvs:
        raise ValueError(f"{root / 'uwf'}: missing Benign or Reconnaissance CSV")
    raw_root = root / "uwf" / "raw"
    raw_root.mkdir(parents=True, exist_ok=True)
    raw_conn = raw_root / "conn.log"
    seen: set[str] = set()
    rows: list[dict] = []
    with raw_conn.open("w", encoding="utf-8") as handle:
        for row in _uwf_conn_rows([*benign_csvs, *recon_csvs]):
            if row["uid"] in seen:
                continue
            seen.add(row["uid"])
            _write_conn_record(handle, row["obj"])
            rows.append(row)
    if not rows:
        raise ValueError(f"{raw_conn}: no UWF conn rows")

    benign: list[GroundTruthRun] = []
    buckets: dict[int, list[dict]] = defaultdict(list)
    for row in rows:
        if row["binary"] in {"false", "0", "benign"}:
            buckets[math.floor(row["ts"] / 600.0) * 600].append(row)
    for bucket in sorted(buckets):
        group = buckets[bucket]
        benign.append(
            GroundTruthRun(
                run_id=f"uwf-benign-{bucket}",
                scenario="benign",
                kind="benign",
                variant="uwf-benign",
                start_ts=_utc(bucket),
                end_ts=_utc(bucket + 600),
                attacker_ip="0.0.0.0",
                victim_ip="0.0.0.0",
                tool="uwf",
                expected_detection=["D1"],
                notes="UWF benign conn",
            )
        )
    if not benign:
        raise ValueError(f"{raw_conn}: no UWF benign rows")

    recon: dict[tuple[str, int], list[dict]] = defaultdict(list)
    for row in rows:
        if row["tactic"] != "reconnaissance":
            continue
        if row["binary"] not in {"true", "1", "attack"}:
            continue
        bucket = math.floor(row["ts"] / 600.0) * 600
        recon[(row["src"], bucket)].append(row)
    attacks: list[GroundTruthRun] = []
    for (src, bucket), group in sorted(recon.items()):
        if len(group) < 10:
            continue
        victim = Counter(row["dst"] for row in group).most_common(1)[0][0]
        technique = group[0]["technique"]
        attacks.append(
            GroundTruthRun(
                run_id=_safe_id(f"uwf-recon-{bucket}-{src}"),
                scenario="port_scan",
                kind="attack",
                variant="uwf-recon",
                start_ts=_utc(bucket),
                end_ts=_utc(bucket + 600),
                attacker_ip=src,
                victim_ip=victim,
                tool="uwf",
                mitre_tactic=["TA0043"],
                mitre_technique=(
                    [technique]
                    if technique and technique.lower() != "none"
                    else []
                ),
                expected_detection=["D2"],
                notes="UWF reconnaissance conn",
            )
        )
    return UwfData(raw_root=raw_root, benign_runs=benign, attack_runs=attacks)


def _replay_pcap(
    pcap: Path,
    out_dir: Path,
    zeek: str,
    required_logs: Sequence[str],
) -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [zeek, "-C", "-r", str(pcap), "LogAscii::use_json=T"],
        cwd=out_dir,
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise ValueError(
            f"{pcap}: zeek failed with {result.returncode}: "
            f"{result.stderr.strip()[:300]}"
        )
    missing = [
        f"{name}.log"
        for name in ("conn", *required_logs)
        if not (out_dir / f"{name}.log").is_file()
    ]
    if missing:
        raise ValueError(f"{pcap}: missing Zeek logs {', '.join(missing)}")


def _read_bounds(raw_root: Path) -> tuple[float, float]:
    records = list(iter_conn_jsonl(raw_root / "conn.log"))
    if not records:
        raise ValueError(f"{raw_root / 'conn.log'}: no conn records")
    return min(record.ts for record in records), max(record.ts for record in records)


def _cic_labels(csv_paths: Sequence[Path]) -> list[dict]:
    rows: list[dict] = []
    for path in csv_paths:
        with path.open(
            "r", encoding="utf-8", errors="replace", newline=""
        ) as handle:
            reader = csv.DictReader(handle)
            if reader.fieldnames is None:
                raise ValueError(f"{path}: missing CSV header")
            fields = {str(name).strip() for name in reader.fieldnames}
            missing = {"Timestamp", "Label", "Source IP", "Destination IP"} - fields
            if missing:
                # The official archives also contain MachineLearningCVE CSVs
                # without timestamps/source IPs; only TrafficLabelling is usable.
                continue
            for lineno, raw in enumerate(reader, start=2):
                row = {str(key).strip(): value for key, value in raw.items()}
                where = f"{path}:{lineno}"
                try:
                    timestamp = _parse_ts(row.get("Timestamp", ""), where)
                except ValueError:
                    continue
                label = (row.get("Label") or "").strip().lower()
                if label not in {
                    "benign",
                    "ftp-patator",
                    "ssh-patator",
                    "bot",
                    "portscan",
                }:
                    continue
                rows.append(
                    {
                        "ts": timestamp,
                        "label": label,
                        "src": (row.get("Source IP") or "").strip(),
                        "dst": (row.get("Destination IP") or "").strip(),
                    }
                )
    if not rows:
        raise ValueError("CIC label CSV contains no rows")
    return rows


def _find_day_pcap(cic_dir: Path, day: str) -> Path | None:
    matches = sorted(
        path
        for path in cic_dir.glob("*.pcap")
        if day in path.name.lower()
    )
    if len(matches) > 1:
        raise ValueError(
            f"{cic_dir}: multiple {day} PCAPs; merge with mergecap first"
        )
    return matches[0] if matches else None


def _prepare_cic(root: Path, zeek: str) -> CicData:
    root = Path(root).resolve()
    cic_dir = root / "cic-ids-2017"
    tuesday = _find_day_pcap(cic_dir, "tuesday")
    friday = _find_day_pcap(cic_dir, "friday")
    if tuesday is None or friday is None:
        raise ValueError(f"{cic_dir}: Tuesday and Friday PCAPs are required")
    label_csvs = [
        path
        for path in sorted(cic_dir.rglob("*.csv"))
        if any(
            day in path.name.lower()
            for day in ("tuesday", "friday", "monday")
        )
    ]
    labels = _cic_labels(label_csvs)
    temp_root = root / ".tmp"
    temp_root.mkdir(parents=True, exist_ok=True)
    cache_root = cic_dir / "raw"
    temp_paths: list[Path] = []

    def day_raw(day: str, pcap: Path, required: Sequence[str]) -> Path:
        cached = cache_root / day
        if (cached / "conn.log").is_file():
            return cached
        cached.mkdir(parents=True, exist_ok=True)
        _replay_pcap(pcap, cached, zeek, required_logs=required)
        return cached

    try:
        tuesday_raw = day_raw(
            "tuesday", tuesday, required=("ssh", "ftp", "http")
        )
        friday_raw = day_raw("friday", friday, required=())
        monday_pcap = _find_day_pcap(cic_dir, "monday")
        monday_raw: Path | None = None
        monday_bounds: tuple[float, float] | None = None
        if monday_pcap is not None:
            monday_raw = day_raw("monday", monday_pcap, required=("http",))
            monday_bounds = _read_bounds(monday_raw)
        return CicData(
            tuesday_raw=tuesday_raw,
            friday_raw=friday_raw,
            monday_raw=monday_raw,
            labels=labels,
            tuesday_bounds=_read_bounds(tuesday_raw),
            friday_bounds=_read_bounds(friday_raw),
            monday_bounds=monday_bounds,
            temp_paths=tuple(temp_paths),
        )
    except Exception:
        for path in temp_paths:
            shutil.rmtree(path, ignore_errors=True)
        raise


def _labels_between(
    labels: Sequence[dict],
    bounds: tuple[float, float],
) -> list[dict]:
    start, end = bounds
    return [row for row in labels if start <= row["ts"] <= end + 1]


def _windows(
    low: float,
    high: float,
    count: int,
    seconds: int,
) -> list[tuple[float, float]]:
    if high <= low:
        raise ValueError("cannot split an empty label interval")
    step = seconds if seconds * count <= high - low else (high - low) / count
    windows: list[tuple[float, float]] = []
    for index in range(count):
        start = low + index * step
        end = min(start + step, high + 1)
        if end > start:
            windows.append((start, end))
    if len(windows) < count:
        raise ValueError(f"need {count} non-empty windows, got {len(windows)}")
    return windows


def _run(
    run_id: str,
    scenario: str,
    kind: str,
    variant: str,
    start: float,
    end: float,
    attacker: str | None,
    victim: str | None,
    tool: str,
    tactic: Sequence[str],
    technique: Sequence[str],
    expected: Sequence[str],
    notes: str,
) -> GroundTruthRun:
    return GroundTruthRun(
        run_id=_safe_id(run_id),
        scenario=scenario,
        kind=kind,
        variant=variant,
        start_ts=_utc(start),
        end_ts=_utc(end),
        attacker_ip=attacker,
        victim_ip=victim,
        tool=tool,
        mitre_tactic=list(tactic),
        mitre_technique=list(technique),
        expected_detection=list(expected),
        notes=notes,
    )


def _attack_windows(
    labels: Sequence[dict],
    token: str,
    count: int,
    seconds: int,
    scenario: str,
    tool: str,
    tactic: Sequence[str],
    technique: Sequence[str],
    expected: Sequence[str],
) -> list[GroundTruthRun]:
    rows = [row for row in labels if token in row["label"]]
    if not rows:
        raise ValueError(f"CIC labels contain no {token}")
    low = min(row["ts"] for row in rows)
    high = max(row["ts"] for row in rows)
    attacker = Counter(row["src"] for row in rows).most_common(1)[0][0]
    victim = Counter(row["dst"] for row in rows).most_common(1)[0][0]
    return [
        _run(
            f"cic-{token.lower()}-{index}",
            scenario,
            "attack",
            token,
            start,
            end,
            attacker,
            victim,
            tool,
            tactic,
            technique,
            expected,
            f"CIC {token}",
        )
        for index, (start, end) in enumerate(
            _windows(low, high, count, seconds), start=1
        )
    ]


def _benign_windows(
    labels: Sequence[dict],
    count: int,
    seconds: int,
    expected: Sequence[str],
    prefix: str,
) -> list[GroundTruthRun]:
    rows = [row for row in labels if row["label"] == "benign"]
    if not rows:
        raise ValueError("CIC labels contain no BENIGN rows")
    low = min(row["ts"] for row in rows)
    high = max(row["ts"] for row in rows)
    return [
        _run(
            f"{prefix}-{index}",
            "benign",
            "benign",
            "cic-benign",
            start,
            end,
            "0.0.0.0",
            "0.0.0.0",
            "cic",
            (),
            (),
            expected,
            f"CIC benign {prefix}",
        )
        for index, (start, end) in enumerate(
            _windows(low, high, count, seconds), start=1
        )
    ]


def _auth_benign_windows(
    raw_root: Path,
    attack_runs: Sequence[GroundTruthRun],
    count: int = 6,
    seconds: int = 1200,
    min_group: int = 3,
) -> list[GroundTruthRun]:
    groups: Counter[tuple[str, str, int]] = Counter()
    group_seconds = 300
    for name in ("ssh", "ftp"):
        path = raw_root / f"{name}.log"
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            conn_id = obj.get("id") or {}
            src = conn_id.get("orig_h") or obj.get("id.orig_h")
            if not src:
                continue
            bucket = math.floor(float(obj["ts"]) / group_seconds) * group_seconds
            groups[(src, name, bucket)] += 1
    max_per_bucket: Counter[int] = Counter()
    for (_, _, group_bucket), count_events in groups.items():
        bucket = math.floor(group_bucket / seconds) * seconds
        max_per_bucket[bucket] = max(max_per_bucket[bucket], count_events)
    attack_ranges = [
        (run.start_ts.timestamp(), run.end_ts.timestamp())
        for run in attack_runs
    ]

    def overlaps(bucket: int) -> bool:
        # Keep a 15-minute guard band around attack windows; CIC labels have
        # minute-level edges and the 20-minute buckets would otherwise absorb
        # attack traffic as benign.
        return any(
            bucket < attack_end + 900 and bucket + seconds > attack_start - 900
            for attack_start, attack_end in attack_ranges
        )

    buckets = [
        bucket
        for bucket in sorted(max_per_bucket)
        if max_per_bucket[bucket] >= min_group and not overlaps(bucket)
    ][:count]
    if len(buckets) < count:
        raise ValueError(
            f"D3 needs {count} benign windows with auth events, got {len(buckets)}"
        )
    return [
        _run(
            f"d3-benign-{index:02d}",
            "benign",
            "benign",
            "cic-benign",
            bucket,
            bucket + seconds,
            "0.0.0.0",
            "0.0.0.0",
            "cic",
            (),
            (),
            ["D3"],
            "CIC benign auth",
        )
        for index, bucket in enumerate(buckets, start=1)
    ]


def _bot_runs(labels: Sequence[dict]) -> list[GroundTruthRun]:
    groups: dict[tuple[str, int], list[dict]] = defaultdict(list)
    for row in labels:
        if row["label"] != "bot":
            continue
        if not row["src"].startswith("192.168.10."):
            continue
        bucket = math.floor(row["ts"] / 600.0) * 600
        groups[(row["src"], bucket)].append(row)
    runs: list[GroundTruthRun] = []
    for (src, bucket), group in sorted(groups.items()):
        if len(group) < 10:
            continue
        victim = Counter(row["dst"] for row in group).most_common(1)[0][0]
        runs.append(
            _run(
                f"cic-bot-{bucket}-{src}",
                "c2_beaconing",
                "attack",
                "cic-bot",
                bucket,
                bucket + 600,
                src,
                victim,
                "cic-botnet",
                ["TA0011"],
                ["T1071"],
                ["D5"],
                "CIC botnet",
            )
        )
    return runs


def _portscan_runs(labels: Sequence[dict]) -> list[GroundTruthRun]:
    rows = [row for row in labels if row["label"] == "portscan"]
    if not rows:
        raise ValueError("CIC labels contain no PortScan rows")
    low = min(row["ts"] for row in rows)
    high = max(row["ts"] for row in rows)
    attacker = Counter(row["src"] for row in rows).most_common(1)[0][0]
    victim = Counter(row["dst"] for row in rows).most_common(1)[0][0]
    return [
        _run(
            f"cic-portscan-{index}",
            "port_scan",
            "attack",
            "cic-portscan",
            start,
            end,
            attacker,
            victim,
            "cic",
            ["TA0043"],
            ["T1046"],
            ["D2"],
            "CIC PortScan",
        )
        for index, (start, end) in enumerate(
            _windows(low, high, 6, 120), start=1
        )
    ]


def _materialize_all(
    raw_root: Path,
    runs: Sequence[GroundTruthRun],
    out_dir: Path,
) -> list[Path]:
    return prepare_lab_runs([raw_root], runs, out_dir)


def _materialize_one(
    raw_root: Path,
    run: GroundTruthRun,
    parent: Path,
) -> Path:
    parent.mkdir(parents=True, exist_ok=True)
    temp = Path(tempfile.mkdtemp(prefix=f".{_safe_id(run.run_id)}-"))
    try:
        prepare_lab_runs([raw_root], [run], temp)
        destination = parent / run.run_id
        shutil.move(str(temp / run.run_id), str(destination))
        return destination
    finally:
        shutil.rmtree(temp, ignore_errors=True)


def _link_run(source: Path, destination: Path) -> None:
    if destination.exists():
        raise ValueError(f"{destination}: already exists")
    destination.symlink_to(os.path.relpath(source, destination.parent))


def _has_lines(path: Path) -> bool:
    if not path.is_file():
        return False
    with path.open("r", encoding="utf-8") as handle:
        return any(line.strip() for line in handle)


def _assert_attacker(run_dir: Path, attacker: str | None) -> None:
    if not attacker:
        raise ValueError(f"{run_dir}: attack run has no attacker_ip")
    for name in ("conn", "dns", "ssh", "ftp", "http"):
        path = run_dir / f"{name}.jsonl"
        if not path.is_file():
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            obj = json.loads(line)
            conn_id = obj.get("id")
            if isinstance(conn_id, dict):
                origin = conn_id.get("orig_h")
            else:
                origin = obj.get("id.orig_h")
            if origin == attacker:
                return
    raise ValueError(f"{run_dir}: attacker_ip {attacker} absent from logs")


def _repair_attacker(run: GroundTruthRun, run_dir: Path) -> GroundTruthRun:
    """Use the observed scan source when a CIC label uses a NAT address."""
    stats: dict[str, tuple[set[int], set[str], int]] = {}
    path = run_dir / "conn.jsonl"
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        conn_id = obj.get("id") or {}
        src = conn_id.get("orig_h") or obj.get("id.orig_h")
        if not src:
            continue
        ports, hosts, count = stats.get(src, (set(), set(), 0))
        ports.add(conn_id.get("resp_p") or obj.get("id.resp_p"))
        hosts.add(conn_id.get("resp_h") or obj.get("id.resp_h"))
        stats[src] = (ports, hosts, count + 1)
    if not stats:
        raise ValueError(f"{run_dir}: cannot repair attacker_ip")
    source = max(
        stats,
        key=lambda item: (
            len(stats[item][0]) * len(stats[item][1]),
            len(stats[item][0]),
            stats[item][2],
        ),
    )
    repaired = run.model_copy(update={"attacker_ip": source})
    (run_dir / "run.json").write_text(
        repaired.model_dump_json(indent=2), encoding="utf-8"
    )
    return repaired


def _prepare_mta(root: Path, out_d4: Path, zeek: str) -> list[GroundTruthRun]:
    root = Path(root).resolve()
    pcaps = sorted((root / "mta").glob("*.pcap"))
    if not pcaps:
        raise ValueError(f"{root / 'mta'}: no MTA PCAPs")
    runs: list[GroundTruthRun] = []
    for pcap in pcaps:
        if len(runs) >= 6:
            break
        with tempfile.TemporaryDirectory(prefix="ndr-mta-") as temp_name:
            raw_root = Path(temp_name)
            try:
                _replay_pcap(
                    pcap,
                    raw_root,
                    zeek,
                    required_logs=("http", "files"),
                )
            except ValueError:
                continue
            http_path = raw_root / "http.log"
            files_path = raw_root / "files.log"
            files = {record.fuid: record for record in iter_files_jsonl(files_path)}
            chosen = None
            for record in iter_http_jsonl(http_path):
                file_record = files.get(record.fuid or "")
                if file_record is None:
                    continue
                ext = Path(file_record.filename or "").suffix.lower().lstrip(".")
                mime = (file_record.mime_type or "").lower()
                if ext in MTA_EXECUTABLE_EXTENSIONS or "dosexec" in mime or "msdownload" in mime:
                    chosen = (record, file_record)
                    break
            if chosen is None:
                continue
            http, file_record = chosen
            start = min(http.ts, file_record.ts)
            end = max(http.ts, file_record.ts) + 1.0
            run = _run(
                f"mta-{pcap.stem}",
                "malware_download",
                "attack",
                "mta",
                start,
                end,
                http.orig_h,
                http.resp_h,
                "mta",
                ["TA0011"],
                ["T1105"],
                ["D4"],
                "MTA download",
            )
            run_dir = _materialize_one(raw_root, run, out_d4)
            with (run_dir / "intel.jsonl").open("w", encoding="utf-8") as handle:
                for value, kind in (
                    (file_record.md5, "md5"),
                    (file_record.sha1, "sha1"),
                    (file_record.sha256, "sha256"),
                ):
                    if value:
                        handle.write(
                            json.dumps(
                                {
                                    "ts": file_record.ts,
                                    "indicator": value.lower(),
                                    "indicator_type": kind,
                                },
                                sort_keys=True,
                            )
                            + "\n"
                        )
            _assert_attacker(run_dir, run.attacker_ip)
            runs.append(run)
    if len(runs) < 6:
        raise ValueError(
            f"D4 needs 6 MTA PCAPs with an HTTP file download; found {len(runs)}"
        )
    return runs


def _prepare_dns(
    root: Path,
    out_d7: Path,
    zeek: str,
) -> tuple[list[GroundTruthRun], list[GroundTruthRun]]:
    root = Path(root).resolve()
    normal_paths = sorted(
        (root / "graph-tunnel" / "normal" / "normal").glob("normal_*.pcap")
    )[:12]
    attack_paths = sorted(
        [
            *(root / "graph-tunnel" / "tunnel").glob("*.pcap"),
            *(root / "graph-tunnel" / "tunnel").glob("*/*.pcap"),
        ]
    )
    if not normal_paths or not attack_paths:
        raise ValueError(f"{root / 'graph-tunnel'}: missing normal or tunnel PCAPs")

    def build(path: Path, attack: bool) -> GroundTruthRun | None:
        with tempfile.TemporaryDirectory(prefix="ndr-dns-") as temp_name:
            raw_root = Path(temp_name)
            try:
                _replay_pcap(path, raw_root, zeek, required_logs=("dns",))
            except ValueError:
                return None
            records = list(iter_dns_jsonl(raw_root / "dns.log"))
            if not records:
                return None
            start = min(record.ts for record in records)
            end = max(record.ts for record in records) + 1.0
            attacker = Counter(record.orig_h for record in records).most_common(1)[0][0]
            victim = Counter(record.resp_h for record in records).most_common(1)[0][0]
            run = _run(
                f"d7-{_safe_id(str(path.relative_to(root / 'graph-tunnel')))}",
                "dns_tunneling" if attack else "benign",
                "attack" if attack else "benign",
                "graph-tunnel" if attack else "graph-tunnel-normal",
                start,
                end,
                attacker if attack else "0.0.0.0",
                victim if attack else "0.0.0.0",
                "graph-tunnel",
                ["TA0011"] if attack else [],
                ["T1048"] if attack else [],
                ["D7"],
                "GraphTunnel DNS",
            )
            run_dir = _materialize_one(raw_root, run, out_d7)
            if attack:
                _assert_attacker(run_dir, run.attacker_ip)
            return run

    attacks = [
        run
        for path in attack_paths
        if (run := build(path, attack=True)) is not None
    ]
    normal: list[GroundTruthRun] = []
    for path in normal_paths:
        run = build(path, attack=False)
        if run is not None:
            normal.append(run)
    if len(attacks) < 6 or len(normal) < 6:
        raise ValueError(
            f"D7 needs >=6 attack and >=6 benign runs; got "
            f"{len(attacks)} attack and {len(normal)} benign"
        )
    return normal, attacks


def _count_runs(path: Path) -> int:
    if not path.is_dir():
        return 0
    return sum(
        1
        for child in path.iterdir()
        if child.is_dir() and (child / "run.json").is_file()
    )


def prepare_datasets(
    root: Path,
    out_dir: Path,
    seed: int = 42,
    zeek: str = "zeek",
) -> dict:
    root = Path(root).resolve()
    out_dir = Path(out_dir).resolve()
    if not root.is_dir():
        raise ValueError(f"{root}: dataset root not found")
    _ensure_empty(out_dir, "output directory")
    out_dir.mkdir(parents=True, exist_ok=True)
    for name in DETECTOR_DIRS.values():
        (out_dir / name).mkdir()

    cic: CicData | None = None
    try:
        uwf = _prepare_uwf(root)
        cic = _prepare_cic(root, zeek)

        tuesday_labels = _labels_between(cic.labels, cic.tuesday_bounds)
        friday_labels = _labels_between(cic.labels, cic.friday_bounds)

        d3_attacks = [
            *_attack_windows(
                tuesday_labels,
                "ftp-patator",
                3,
                1200,
                "brute_force",
                "patator",
                ["TA0006"],
                ["T1110"],
                ["D3"],
            ),
            *_attack_windows(
                tuesday_labels,
                "ssh-patator",
                3,
                1200,
                "brute_force",
                "patator",
                ["TA0006"],
                ["T1110"],
                ["D3"],
            ),
        ]
        # D3's fixed test split is benign[5:]; every split needs at least one
        # benign auth window, so select auth-rich windows outside attacks.
        d3_benign = _auth_benign_windows(
            cic.tuesday_raw,
            d3_attacks,
            count=6,
            seconds=1200,
        )
        d3_runs = [*d3_attacks, *d3_benign]
        _materialize_all(cic.tuesday_raw, d3_runs, out_dir / "d3")
        d3_paths = {run.run_id: out_dir / "d3" / run.run_id for run in d3_runs}
        for run in d3_attacks:
            _assert_attacker(d3_paths[run.run_id], run.attacker_ip)
        d3_benign_paths = [d3_paths[run.run_id] for run in d3_benign]
        if not all(_has_lines(path / "http.jsonl") for path in d3_benign_paths):
            if cic.monday_raw is None or cic.monday_bounds is None:
                raise ValueError(
                    "D4 benign requires HTTP in CIC benign windows; "
                    "provide the Monday PCAP"
                )
            monday_labels = _labels_between(cic.labels, cic.monday_bounds)
            monday_benign = _benign_windows(
                monday_labels, 6, 1200, ["D4"], "d4-benign"
            )
            for run in monday_benign:
                path = _materialize_one(cic.monday_raw, run, out_dir / "d4")
                if not _has_lines(path / "http.jsonl"):
                    raise ValueError(
                        f"{path}: D4 benign window has no HTTP events"
                    )
        else:
            for path in d3_benign_paths:
                _link_run(path, out_dir / "d4" / path.name)

        d5_attacks = _bot_runs(friday_labels)
        if len(d5_attacks) < 6:
            raise ValueError(
                f"D5 needs >=6 CIC botnet runs, got {len(d5_attacks)}"
            )
        _materialize_all(cic.friday_raw, d5_attacks, out_dir / "d5")
        for run in d5_attacks:
            _assert_attacker(out_dir / "d5" / run.run_id, run.attacker_ip)

        d5_benign: list[GroundTruthRun] = []
        for run in _benign_windows(friday_labels, 6, 600, ["D5"], "d5-benign"):
            try:
                _materialize_one(cic.friday_raw, run, out_dir / "d5")
            except ValueError:
                continue
            d5_benign.append(run)
        if len(d5_benign) < 6:
            d5_benign = []
            for run in _benign_windows(
                tuesday_labels, 6, 600, ["D5"], "d5-tue-benign"
            ):
                try:
                    _materialize_one(cic.tuesday_raw, run, out_dir / "d5")
                except ValueError:
                    continue
                d5_benign.append(run)
        if len(d5_benign) < 6:
            raise ValueError(
                f"D5 needs >=6 benign conn windows, got {len(d5_benign)}"
            )

        # UWF provides 800+ ten-minute buckets; 60 is enough for D1's
        # >=100-window requirement and keeps prepare_lab_runs below the
        # per-process open-file limit.
        d1_runs = [*uwf.benign_runs[:60], *d3_benign, *d5_benign]
        prepare_lab_runs(
            [uwf.raw_root, cic.tuesday_raw, cic.friday_raw],
            d1_runs,
            out_dir / "d1",
        )

        d2_runs = uwf.attack_runs
        if len(d2_runs) < 6:
            d2_runs = [
                *d2_runs,
                *_portscan_runs(friday_labels),
            ]
        for run in d2_runs:
            raw = uwf.raw_root if run.run_id.startswith("uwf-") else cic.friday_raw
            path = _materialize_one(raw, run, out_dir / "d2")
            if run.run_id.startswith("cic-portscan-"):
                _repair_attacker(run, path)
            else:
                _assert_attacker(path, run.attacker_ip)
        for path in sorted((out_dir / "d1").iterdir()):
            if path.is_dir() and (path / "run.json").is_file():
                _link_run(path, out_dir / "d2" / path.name)

        _prepare_mta(root, out_dir / "d4", zeek)
        generate_lateral_corpus(out_dir / "d6", seed=seed)
        _prepare_dns(root, out_dir / "d7", zeek)

        runs = {key: _count_runs(out_dir / name) for key, name in DETECTOR_DIRS.items()}
        summary = {
            "runs": runs,
            "sources": {
                "D1": "uwf+cic",
                "D2": "uwf+cic",
                "D3": "cic-ids-2017",
                "D4": "mta+cic-benign",
                "D5": "cic-ids-2017",
                "D6": "synthetic",
                "D7": "graph-tunnel",
            },
        }
        (out_dir / "summary.json").write_text(
            json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
        )
        return summary
    finally:
        if cic is not None:
            for path in cic.temp_paths:
                shutil.rmtree(path, ignore_errors=True)


def train_datasets(
    runs_dir: Path,
    models_dir: Path,
    seed: int = 42,
) -> dict:
    runs_dir = Path(runs_dir)
    models_dir = Path(models_dir)
    if not runs_dir.is_dir():
        raise ValueError(f"{runs_dir}: runs directory not found")
    _ensure_empty(models_dir, "models directory")
    models_dir.mkdir(parents=True, exist_ok=True)

    metadata = {
        "D1": train(
            input_dir=runs_dir / "d1",
            out_dir=models_dir / "anomaly",
            seed=seed,
        ),
        "D2": train_scan(
            input_dir=runs_dir / "d2",
            out_dir=models_dir / "scan",
            seed=seed,
        ),
        "D3": train_brute(
            input_dir=runs_dir / "d3",
            out_dir=models_dir / "brute",
            seed=seed,
            min_events=3,
        ),
        "D4": train_malware(
            input_dir=runs_dir / "d4",
            out_dir=models_dir / "malware",
            seed=seed,
        ),
        "D5": train_beacon(
            input_dir=runs_dir / "d5",
            out_dir=models_dir / "beacon",
            seed=seed,
        ),
        "D6": train_lateral(
            input_dir=runs_dir / "d6",
            out_dir=models_dir / "lateral",
            seed=seed,
        ),
        "D7": train_dns(
            input_dir=runs_dir / "d7",
            out_dir=models_dir / "dns",
            seed=seed,
            min_events=1,
        ),
    }
    summary = {
        "detectors": {
            key: {
                "model": model.model_name,
                "threshold": model.threshold,
                "metrics": model.metrics,
            }
            for key, model in metadata.items()
        }
    }
    (models_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )
    return summary
