"""Module with choices using in forms and models."""

from django.db.models import TextChoices


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


class ScanRiskLevelChoices(TextChoices):
    """Choices for presenting the final scan result."""

    healthy = 'A'
    low = 'B'
    medium = 'C'
    high = 'D'
