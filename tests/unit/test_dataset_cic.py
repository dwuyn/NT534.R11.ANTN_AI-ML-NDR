from __future__ import annotations

import csv
from pathlib import Path

from ndr.datasets import (
    _attack_windows,
    _bot_runs,
    _cic_labels,
    _portscan_runs,
)


def _labels() -> list[dict]:
    return [
        {
            "ts": 1000.0 + index * 10,
            "label": "ftp-patator",
            "src": "205.174.165.73",
            "dst": "205.174.165.68",
        }
        for index in range(6)
    ] + [
        {
            "ts": 2000.0 + index * 10,
            "label": "ssh-patator",
            "src": "205.174.165.73",
            "dst": "205.174.165.68",
        }
        for index in range(6)
    ]


def test_cic_label_parsing(tmp_path: Path) -> None:
    path = tmp_path / "labels.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["Timestamp", "Label", "Source IP", "Destination IP"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "Timestamp": "04/07/2017 09:20:00",
                "Label": "FTP-Patator",
                "Source IP": "205.174.165.73",
                "Destination IP": "205.174.165.68",
            }
        )
        writer.writerow(
            {
                "Timestamp": "2017-07-04 14:00",
                "Label": "BENIGN",
                "Source IP": "10.0.0.1",
                "Destination IP": "10.0.0.2",
            }
        )
    rows = _cic_labels([path])
    assert len(rows) == 2
    assert rows[0]["label"] == "ftp-patator"
    assert rows[1]["label"] == "benign"


def test_cic_attack_and_portscan_windows() -> None:
    labels = _labels()
    ftp = _attack_windows(
        labels,
        "ftp-patator",
        3,
        1200,
        "brute_force",
        "patator",
        ["TA0006"],
        ["T1110"],
        ["D3"],
    )
    ssh = _attack_windows(
        labels,
        "ssh-patator",
        3,
        1200,
        "brute_force",
        "patator",
        ["TA0006"],
        ["T1110"],
        ["D3"],
    )
    assert len(ftp) == 3
    assert len(ssh) == 3
    assert ftp[0].attacker_ip == "205.174.165.73"
    assert ftp[0].expected_detection == ["D3"]

    portscan = _portscan_runs(
        [
            {
                "ts": 1000.0 + index,
                "label": "portscan",
                "src": "205.174.165.73",
                "dst": "205.174.165.68",
            }
            for index in range(100)
        ]
    )
    assert len(portscan) == 6


def test_cic_bot_runs_require_six_groups() -> None:
    labels = []
    for group in range(6):
        for index in range(10):
            labels.append(
                {
                    "ts": 1000.0 + group * 1000 + index,
                    "label": "bot",
                    "src": f"192.168.10.{group + 1}",
                    "dst": "203.0.113.5",
                }
            )
    runs = _bot_runs(labels)
    assert len(runs) == 6
    assert all(run.attacker_ip.startswith("192.168.10.") for run in runs)
