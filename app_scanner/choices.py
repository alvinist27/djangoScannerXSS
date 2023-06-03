"""Module with choices using in forms and models."""

from django.db.models import IntegerChoices, TextChoices


class XSSVulnerabilityTypeChoices(TextChoices):
    """Choices for selecting XSS vulnerability type."""

    reflected = 'R', 'Reflected'
    stored = 'S', 'Stored'
    dom_based = 'D', 'DOM-based'
    full = 'F', 'Full scan'


class ScanStatusChoices(TextChoices):
    """Choices for tracking current scan result."""

    started = 'S', 'Started'
    error = 'E', 'Error'
    completed = 'C', 'Completed'


class ScanRiskLevelChoices(IntegerChoices):
    """Choices for presenting the final scan result."""

    healthy = 0, 'A'
    low = 5, 'B'
    medium = 10, 'C'
    high = 25, 'D'
