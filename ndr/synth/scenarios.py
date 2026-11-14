"""Fixed synthetic run definitions."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

BASE_TS = 1770000000.0

ATTACKER_IP = "192.168.217.132"


@dataclass(frozen=True)
class RunSpec:
    scenario: str
    kind: Literal["benign", "attack"]
    variant: str
    tool: str
    attacker_ip: str | None
    victim_ip: str | None
    mitre_tactic: tuple[str, ...]
    mitre_technique: tuple[str, ...]
    expected_detection: tuple[str, ...]


BENIGN_SPECS: tuple[RunSpec, ...] = (
    RunSpec(
        scenario="benign_browsing",
        kind="benign",
        variant="standard",
        tool="synthetic_browser",
        attacker_ip=None,
        victim_ip=None,
        mitre_tactic=(),
        mitre_technique=(),
        expected_detection=(),
    ),
    RunSpec(
        scenario="benign_admin",
        kind="benign",
        variant="standard",
        tool="ssh_admin",
        attacker_ip=None,
        victim_ip=None,
        mitre_tactic=(),
        mitre_technique=(),
        expected_detection=(),
    ),
    RunSpec(
        scenario="benign_update",
        kind="benign",
        variant="standard",
        tool="update_client",
        attacker_ip=None,
        victim_ip=None,
        mitre_tactic=(),
        mitre_technique=(),
        expected_detection=(),
    ),
)

ATTACK_SPECS: tuple[RunSpec, ...] = (
    RunSpec(
        scenario="attack_fast_scan",
        kind="attack",
        variant="vertical_200_ports",
        tool="synthetic_scan",
        attacker_ip=ATTACKER_IP,
        victim_ip="192.168.217.129",
        mitre_tactic=("TA0007",),
        mitre_technique=("T1046",),
        expected_detection=("D1",),
    ),
    RunSpec(
        scenario="attack_slow_scan",
        kind="attack",
        variant="slow_40_conns",
        tool="synthetic_scan",
        attacker_ip=ATTACKER_IP,
        victim_ip="192.168.217.129",
        mitre_tactic=("TA0007",),
        mitre_technique=("T1046",),
        expected_detection=("D1",),
    ),
    RunSpec(
        scenario="attack_beacon",
        kind="attack",
        variant="6s_interval",
        tool="synthetic_beacon",
        attacker_ip=ATTACKER_IP,
        victim_ip="192.168.217.129",
        mitre_tactic=("TA0011",),
        mitre_technique=("T1071.001", "T1573"),
        expected_detection=("D1",),
    ),
    RunSpec(
        scenario="attack_exfil",
        kind="attack",
        variant="burst_20_conns",
        tool="synthetic_exfil",
        attacker_ip=ATTACKER_IP,
        victim_ip="192.168.217.129",
        mitre_tactic=("TA0010", "TA0011"),
        mitre_technique=("T1048", "T1071.004"),
        expected_detection=("D1",),
    ),
)
