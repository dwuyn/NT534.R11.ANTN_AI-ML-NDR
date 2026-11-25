from __future__ import annotations

import csv
import json
from pathlib import Path

from ndr.datasets import _prepare_uwf

HEADERS = [
    "community_id",
    "conn_state",
    "duration",
    "history",
    "src_ip_zeek",
    "src_port_zeek",
    "dest_ip_zeek",
    "dest_port_zeek",
    "local_orig",
    "local_resp",
    "missed_bytes",
    "orig_bytes",
    "orig_ip_bytes",
    "orig_pkts",
    "proto",
    "resp_bytes",
    "resp_ip_bytes",
    "resp_pkts",
    "service",
    "ts",
    "uid",
    "datetime",
    "label_tactic",
    "label_technique",
    "label_binary",
    "label_cve",
]


def _write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=HEADERS)
        writer.writeheader()
        writer.writerows(rows)


def _row(ts: str, uid: str, tactic: str, binary: str) -> dict[str, str]:
    return {
        "community_id": "1:test",
        "conn_state": "S0",
        "duration": "",
        "history": "D",
        "src_ip_zeek": "10.0.0.1",
        "src_port_zeek": "40000",
        "dest_ip_zeek": "10.0.0.2",
        "dest_port_zeek": "80",
        "local_orig": "true",
        "local_resp": "false",
        "missed_bytes": "0",
        "orig_bytes": "10",
        "orig_ip_bytes": "20",
        "orig_pkts": "1",
        "proto": "tcp",
        "resp_bytes": "0",
        "resp_ip_bytes": "0",
        "resp_pkts": "0",
        "service": "",
        "ts": ts,
        "uid": uid,
        "datetime": "",
        "label_tactic": tactic,
        "label_technique": "T1595" if tactic != "none" else "none",
        "label_binary": binary,
        "label_cve": "none",
    }


def test_uwf_conversion_dedup_and_runs(tmp_path: Path) -> None:
    benign = tmp_path / "uwf" / "Benign"
    recon = tmp_path / "uwf" / "Reconnaissance"
    benign.mkdir(parents=True)
    recon.mkdir(parents=True)
    _write_csv(
        benign / "part.csv",
        [
            _row("1000", "b1", "none", "False"),
            _row("1001", "b2", "none", "False"),
            _row("1001", "b2", "none", "False"),
        ],
    )
    _write_csv(
        recon / "part.csv",
        [
            _row(str(1000 + index), f"r{index}", "Reconnaissance", "True")
            for index in range(12)
        ],
    )

    data = _prepare_uwf(tmp_path)

    raw_lines = [
        json.loads(line)
        for line in (data.raw_root / "conn.log").read_text(encoding="utf-8").splitlines()
        if line
    ]
    assert len(raw_lines) == 14
    assert len(data.benign_runs) == 1
    assert len(data.attack_runs) == 1
    attack = data.attack_runs[0]
    assert attack.kind == "attack"
    assert attack.scenario == "port_scan"
    assert attack.attacker_ip == "10.0.0.1"
    assert attack.expected_detection == ["D2"]
