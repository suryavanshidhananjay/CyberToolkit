"""Password strength analysis for CyberToolkit.

This module provides a simple evaluator that checks a password against a set
of common criteria and returns a numerical score, textual summary, and a list
of issues/suggestions.  A small built-in list of 50 common passwords is
used to detect dictionary-based weaknesses.

The public entry point is ``analyze_password(password: str)`` which returns a
dictionary containing the results described below.  Color coding is also
provided for external consumers via the ``color`` field (``'red'``, ``'yellow'``
or ``'green'``) based on the score.

"""
from __future__ import annotations

import re
from datetime import timedelta
from typing import Dict, List

# minimal common password list; can be extended later.
_common_passwords = {
    "123456", "password", "12345678", "qwerty", "123456789", "12345",
    "1234", "111111", "1234567", "dragon", "123123", "baseball",
    "abc123", "football", "monkey", "letmein", "696969", "shadow",
    "master", "666666", "qwertyuiop", "123321", "mustang", "1234567890",
    "michael", "654321", "superman", "1qaz2wsx", "7777777", "fuckyou",
    "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1",
    "jordan", "jennifer", "zxcvbnm", "asdfgh", "hunter", "buster",
    "soccer", "harley", "batman", "andrew", "tigger", "sunshine",
    "iloveyou", "fuckme", "2000", "charlie", "robert"  # 50 entries
}

# scoring weights
_LENGTH_WEIGHT = 30
_CHARSET_WEIGHT = 40
_COMMON_WEIGHT = 30


# ---------------------------------------------------------------------------
# helper utilities
# ---------------------------------------------------------------------------

def _estimate_crack_time(password: str) -> str:
    """Produce a human-readable estimate of cracking time.

    This naive implementation calculates entropy based on character set size
    and returns a rough estimate assuming 10^9 guesses/second.
    """

    # approximate charset size
    charset = 0
    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"[0-9]", password):
        charset += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        charset += 32  # rough count of common symbols

    # entropy bits
    entropy = len(password) * (charset.bit_length())
    guesses = 2 ** entropy
    secs = guesses / 1e9
    td = timedelta(seconds=secs)

    if secs < 60:
        return f"{int(secs)} seconds"
    if secs < 3600:
        return f"{int(secs/60)} minutes"
    if secs < 86400:
        return f"{int(secs/3600)} hours"
    if secs < 31536000:
        return f"{int(secs/86400)} days"
    if secs < 3153600000:
        return f"{int(secs/31536000)} years"
    return "centuries"


def _strength_label(score: int) -> str:
    if score < 40:
        return "Weak"
    if score < 55:
        return "Fair"
    if score < 70:
        return "Good"
    if score < 85:
        return "Strong"
    return "Very Strong"


def _color_code(score: int) -> str:
    if score < 40:
        return "red"
    if score <= 70:
        return "yellow"
    return "green"


# ---------------------------------------------------------------------------
# public API
# ---------------------------------------------------------------------------

def analyze_password(password: str) -> Dict[str, object]:
    """Analyse a password and return strength metrics.

    The returned dictionary includes:

    * ``score``: integer 0..100
    * ``strength_label``: textual label
    * ``issues``: list of detected weaknesses
    * ``suggestions``: list of improvements
    * ``estimated_crack_time``: human-readable string
    * ``color``: one of 'red','yellow','green'
    """

    issues: List[str] = []
    suggestions: List[str] = []

    # length check
    if len(password) < 12:
        issues.append("Password is shorter than 12 characters")
        suggestions.append("Use at least 12 characters")
    length_score = min(len(password) * 2, _LENGTH_WEIGHT)

    # charset variety
    upper = bool(re.search(r"[A-Z]", password))
    lower = bool(re.search(r"[a-z]", password))
    digit = bool(re.search(r"[0-9]", password))
    symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

    charset_score = 0
    if upper:
        charset_score += 10
    else:
        suggestions.append("Add uppercase letters")
    if lower:
        charset_score += 10
    else:
        suggestions.append("Add lowercase letters")
    if digit:
        charset_score += 10
    else:
        suggestions.append("Add numbers")
    if symbol:
        charset_score += 10
    else:
        suggestions.append("Add special characters")

    charset_score = min(charset_score, _CHARSET_WEIGHT)

    # common passwords check
    low = password.lower()
    if low in _common_passwords:
        issues.append("Password is a commonly used password")
        common_score = 0
    else:
        common_score = _COMMON_WEIGHT
        # also penalize if it contains a common word
        for word in _common_passwords:
            if word in low:
                issues.append(f"Contains common word: {word}")
                common_score -= 10
    common_score = max(common_score, 0)

    score = length_score + charset_score + common_score
    score = max(0, min(100, int(score)))

    if not issues:
        suggestions.append("Use a mix of length and character types")

    return {
        "score": score,
        "strength_label": _strength_label(score),
        "issues": issues,
        "suggestions": suggestions,
        "estimated_crack_time": _estimate_crack_time(password),
        "color": _color_code(score),
    }


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Analyse a password")
    parser.add_argument("password", help="Password to analyse")
    args = parser.parse_args()
    result = analyze_password(args.password)
    for k, v in result.items():
        print(f"{k}: {v}")
