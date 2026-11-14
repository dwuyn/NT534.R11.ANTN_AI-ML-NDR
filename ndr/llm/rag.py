"""Static playbook retrieval for the mock LLM triage harness.

The playbooks are in-file data: no filesystem, vector store, or network is
used. Unknown scenarios fall back to the generic playbook.
"""

from __future__ import annotations

PLAYBOOKS: dict[str, tuple[str, ...]] = {
    "c2_beaconing": (
        "Confirm the periodic channel by correlating flow intervals and bytes.",
        "Inspect the destination and JA3/JA4 for known C2 infrastructure.",
        "Isolate the source host and block the destination if confirmed.",
    ),
    "dns_tunneling": (
        "Inspect query labels for encoding and unusually long subdomains.",
        "Compare query volume and entropy against the DNS baseline.",
        "Sinkhole or block the tunnelling domain at the resolver.",
    ),
    "port_scan": (
        "Identify the scanning host and the targeted port range.",
        "Check whether any scanned service accepted a follow-on connection.",
        "Rate-limit or isolate the scanner after confirming ownership.",
    ),
    "brute_force": (
        "Verify the failed authentication volume and targeted accounts.",
        "Check for any successful login from the same source.",
        "Lock affected accounts and block the source address.",
    ),
    "malware_download": (
        "Retrieve the downloaded file hash and reputation.",
        "Inspect the URL, host rarity, and content-type mismatch.",
        "Quarantine the host and block the download infrastructure.",
    ),
    "lateral_movement": (
        "Review remote service creation and SMB writes to admin shares.",
        "Identify the compromised credential and source host.",
        "Disable the credential and isolate the affected hosts.",
    ),
    "default": (
        "Preserve the alert evidence and affected entity identifiers.",
        "Correlate the alert with adjacent detections in the kill chain.",
        "Escalate to an analyst before taking disruptive action.",
    ),
}


def retrieve_playbook(scenario: str | None) -> str:
    steps = PLAYBOOKS.get(scenario or "", PLAYBOOKS["default"])
    return "\n".join(f"- {step}" for step in steps)
