"""Module for app_users views."""

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.views.generic.edit import FormView

from app_scanner.choices import XSSVulnerabilityTypeChoices
from app_scanner.forms import ScanForm
from app_scanner.process import ScanProcessSelenium


def main_view(request: HttpRequest) -> HttpResponse:
    """Display the main page of the scanner.

    Args:
        request: HttpRequest object.

    Returns:
        HttpResponse object.
    """
    return render(request, 'app_scanner/index.html')


def about_view(request: HttpRequest) -> HttpResponse:
    """Display page with information about scanner.

    Args:
        request: HttpRequest object.

    Returns:
        HttpResponse object.
    """
    return render(request, 'app_scanner/about.html')


def not_found(request: HttpRequest, *args, **kwargs) -> HttpResponse:
    """Display page for 404 error handling.

    Args:
        request: HttpRequest object.

    Returns:
        HttpResponse object.
    """
    return render(request, 'app_scanner/404.html', status=404)


class ScanFormView(LoginRequiredMixin, FormView):
    """Display scan page."""

    form_class = ScanForm
    success_url = '/'
    template_name = 'app_scanner/scan.html'

    def form_valid(self, scan_form):
        if scan_form.is_valid():
            scan_type = scan_form.cleaned_data['scan_type']
            scan = ScanProcessSelenium(
                target_url=scan_form.cleaned_data['target_url'],
                xss_type=scan_type,
                user_id=self.request.user.id,
                is_cloudflare=scan_form.cleaned_data['is_cloudflare'],
                is_one_page_scan=scan_form.cleaned_data['is_one_page_scan'],
            )
            if scan_type == XSSVulnerabilityTypeChoices.full:
                scan.full_scan()
            elif scan_type == XSSVulnerabilityTypeChoices.reflected:
                scan.scan_reflected_xss()
            elif scan_type == XSSVulnerabilityTypeChoices.stored:
                scan.scan_stored_xss()
            else:
                scan.scan_dom_based_xss()
        return super().form_valid(scan_form)
