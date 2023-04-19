"""Module with app_scanner forms."""

from django import forms

from app_scanner.choices import XSSVulnerabilityTypeChoices


class ScanForm(forms.Form):
    """Form for XSS scanning."""

    target_url = forms.URLField(widget=forms.URLInput(attrs={
        'placeholder': 'https://example.com/',
        'class': 'form-control',
    }))
    scan_type = forms.ChoiceField(
        choices=XSSVulnerabilityTypeChoices.choices,
        widget=forms.Select(attrs={'class': 'form-control'}),
    )
    is_cloudflare = forms.BooleanField(initial=False, required=False)
    is_one_page_scan = forms.BooleanField(initial=False, required=False)
