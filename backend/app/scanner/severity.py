"""Consistent severity / confidence / validation-status classification.

Rules of thumb used by every module:

* ``CONFIRMED``      – the evidence itself demonstrates the weakness (e.g. two independent
                       signals, or an explicit expected-vs-observed permission mismatch).
* ``POTENTIAL``      – suspicious behaviour that needs human verification.
* ``INFORMATIONAL``  – an observation or hardening gap, not a demonstrated vulnerability.
* ``INCONCLUSIVE``   – a test could not be completed; recorded in the report, not as a flaw.
"""

from app.models.enums import Confidence, FindingStatus, Severity

_SEVERITY_RANK = {s: i for i, s in enumerate(Severity)}
_ORDER = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]


def rank(severity: Severity) -> int:
    return _ORDER.index(severity)


def cap_severity(severity: Severity, status: FindingStatus, confidence: Confidence) -> Severity:
    """Never let unvalidated results claim more severity than their evidence supports."""
    if status is FindingStatus.INFORMATIONAL:
        return min(severity, Severity.LOW, key=rank)
    if status is FindingStatus.INCONCLUSIVE:
        return Severity.INFO
    if status is FindingStatus.POTENTIAL and confidence is Confidence.LOW:
        return min(severity, Severity.MEDIUM, key=rank)
    return severity


SEVERITY_RANK_SQL_ORDER = [s.value for s in _ORDER]
