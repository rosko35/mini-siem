"""The subset of MITRE ATT&CK (Enterprise) techniques referenced by the shipped rules.

Rules may reference any technique ID; unknown IDs are accepted and shown
without a name. https://attack.mitre.org/techniques/enterprise/
"""

from __future__ import annotations

import re

TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

TECHNIQUES: dict[str, tuple[str, str]] = {
    # id: (name, tactic)
    "T1110": ("Brute Force", "Credential Access"),
    "T1110.001": ("Brute Force: Password Guessing", "Credential Access"),
    "T1110.003": ("Brute Force: Password Spraying", "Credential Access"),
    "T1110.004": ("Brute Force: Credential Stuffing", "Credential Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1078.003": ("Valid Accounts: Local Accounts", "Initial Access"),
    "T1021.004": ("Remote Services: SSH", "Lateral Movement"),
    "T1595": ("Active Scanning", "Reconnaissance"),
    "T1595.002": ("Active Scanning: Vulnerability Scanning", "Reconnaissance"),
    "T1595.003": ("Active Scanning: Wordlist Scanning", "Reconnaissance"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", "Credential Access"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
}


def technique_name(tid: str) -> str:
    return TECHNIQUES.get(tid, ("", ""))[0]


def technique_tactic(tid: str) -> str:
    return TECHNIQUES.get(tid, ("", ""))[1]


def technique_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"
