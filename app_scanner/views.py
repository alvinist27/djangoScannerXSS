"""Module for app_users views."""

from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from django.views.generic.edit import FormView

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


def contact_view(request: HttpRequest) -> HttpResponse:
    """Display page with contact information.

    Args:
        request: HttpRequest object.

    Returns:
        HttpResponse object.
    """
    return render(request, 'app_scanner/contact.html')


def not_found(request: HttpRequest) -> HttpResponse:
    """Display page for 404 error handling.

    Args:
        request: HttpRequest object.

    Returns:
        HttpResponse object.
    """
    return render(request, 'app_scanner/404.html')


def project_view(request: HttpRequest) -> HttpResponse:
    """Display page with information about project.

    Args:
        request: HttpRequest object.

    Returns:
        HttpResponse object.
    """
    return render(request, 'app_scanner/project.html')


def service_view(request: HttpRequest) -> HttpResponse:
    """Display page with information about service.

    Args:
        request: HttpRequest object.

    Returns:
        HttpResponse object.
    """
    return render(request, 'app_scanner/service.html')


def team_view(request: HttpRequest) -> HttpResponse:
    """Display page with information about project.

    Args:
        request: HttpRequest object.

    Returns:
        HttpResponse object.
    """
    return render(request, 'app_scanner/team.html')


def testimonial_view(request: HttpRequest) -> HttpResponse:
    """Display page with information about project.

    Args:
        request: HttpRequest object.

    Returns:
        HttpResponse object.
    """
    return render(request, 'app_scanner/testimonial.html')


class ContactFormView(FormView):
    """Display scan page."""

    form_class = ScanForm
    success_url = '/'
    template_name = 'app_scanner/scan.html'

    def form_valid(self, scan_form):
        if scan_form.is_valid():
            target_url = scan_form.cleaned_data['target_url']
            scan_type = scan_form.cleaned_data['scan_type']
            is_cloudflare = scan_form.cleaned_data['is_cloudflare']
            is_one_page_scan = scan_form.cleaned_data['is_one_page_scan']
            scan = ScanProcessSelenium('http://testphp.vulnweb.com/')
            results = scan.scan_reflected_xss()
            for result in results:
                print(result)
        return super().form_valid(scan_form)
