"""AI security advisor for CyberToolkit.

This module interprets security alerts and produces a structured analysis.
It classifies the threat, assigns a risk score, explains the issue, and
generates actionable recommendations.

Public API:
    analyze_alert(alert: str) -> Dict[str, object]
"""

from __future__ import annotations

import re
from typing import Dict, List

# ---------------------------------------------------------------------
# threat patterns
# ---------------------------------------------------------------------

_THREAT_PATTERNS = {
    "brute_force": [
        r"failed login",
        r"multiple login failures",
        r"authentication failure",
    ],
    "file_tampering": [
        r"file modified",
        r"file changed",
        r"checksum mismatch",
    ],
    "malware_activity": [
        r"suspicious process",
        r"unknown executable",
        r"unauthorized script",
    ],
    "privilege_escalation": [
        r"sudo failure",
        r"permission denied",
        r"root access attempt",
    ],
    "network_intrusion": [
        r"port scan",
        r"suspicious connection",
        r"unknown ip",
    ],
}

# base risk scores
_RISK_WEIGHTS = {
    "brute_force": 70,
    "file_tampering": 60,
    "malware_activity": 85,
    "privilege_escalation": 80,
    "network_intrusion": 65,
}

# recommendations
_RECOMMENDATIONS = {
    "brute_force": [
        "Enable account lockout policy",
        "Implement multi-factor authentication",
        "Monitor login attempts",
    ],
    "file_tampering": [
        "Verify file integrity",
        "Check recent system access logs",
        "Restore file from secure backup",
    ],
    "malware_activity": [
        "Terminate suspicious process",
        "Run malware and antivirus scan",
        "Inspect startup services",
    ],
    "privilege_escalation": [
        "Audit privileged accounts",
        "Review sudo access policies",
        "Check for unauthorized root access",
    ],
    "network_intrusion": [
        "Block suspicious IP address",
        "Inspect firewall rules",
        "Monitor network traffic",
    ],
}


# ---------------------------------------------------------------------
# utility functions
# ---------------------------------------------------------------------

def _detect_threat(alert: str) -> str:
    """Detect threat category based on pattern matching."""

    text = alert.lower()

    for threat, patterns in _THREAT_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text):
                return threat

    return "unknown"


def _risk_label(score: int) -> str:
    """Convert risk score to label."""

    if score < 30:
        return "Low"
    if score < 60:
        return "Medium"
    if score < 80:
        return "High"
    return "Critical"


def _generate_explanation(threat: str) -> str:
    """Return explanation for threat."""

    explanations = {
        "brute_force":
        "Repeated authentication failures indicate a possible brute-force attack.",

        "file_tampering":
        "Unexpected file modification may suggest unauthorized system changes.",

        "malware_activity":
        "Execution of an unknown or suspicious process may indicate malware.",

        "privilege_escalation":
        "An attempt to gain elevated permissions was detected.",

        "network_intrusion":
        "Suspicious network activity suggests a potential intrusion attempt.",

        "unknown":
        "No specific threat pattern matched this alert."
    }

    return explanations.get(threat, explanations["unknown"])


def _generate_suggestions(threat: str) -> List[str]:
    """Return recommended actions."""

    if threat in _RECOMMENDATIONS:
        return _RECOMMENDATIONS[threat]

    return [
        "Monitor system logs",
        "Verify system integrity",
        "Investigate unusual activity"
    ]


def _calculate_confidence(alert: str) -> int:
    """Estimate AI confidence level."""

    keywords = [
        "failed", "unauthorized", "suspicious",
        "malware", "denied", "scan"
    ]

    count = sum(1 for k in keywords if k in alert.lower())

    return min(100, count * 15)


# ---------------------------------------------------------------------
# main API
# ---------------------------------------------------------------------

def analyze_alert(alert: str) -> Dict[str, object]:
    """Analyze a security alert and produce structured advisory."""

    threat = _detect_threat(alert)

    base_risk = _RISK_WEIGHTS.get(threat, 20)

    confidence = _calculate_confidence(alert)

    risk_score = min(100, base_risk + confidence // 2)

    result = {
        "alert": alert,
        "detected_threat": threat,
        "risk_score": risk_score,
        "risk_level": _risk_label(risk_score),
        "confidence": confidence,
        "explanation": _generate_explanation(threat),
        "recommendations": _generate_suggestions(threat),
    }

    return result


# ---------------------------------------------------------------------
# CLI testing
# ---------------------------------------------------------------------

if __name__ == "__main__":

    sample = "Multiple failed login attempts detected from unknown IP"

    result = analyze_alert(sample)

    for k, v in result.items():
        print(f"{k}: {v}")