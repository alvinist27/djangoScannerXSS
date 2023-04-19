"""Module with app_scanner forms."""

from django import forms

from app_scanner.choices import XSSVulnerabilityTypeChoices


class ScanForm(forms.Form):
    """Form for XSS scanning."""

    target_url = forms.URLField()
    scan_type = forms.ChoiceField(choices=XSSVulnerabilityTypeChoices.choices)
    is_cloudflare = forms.BooleanField(initial=False)
    is_one_page_scan = forms.BooleanField(initial=False)
