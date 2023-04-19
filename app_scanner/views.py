"""Module for app_users views."""

from django.http import HttpRequest, HttpResponse
from django.shortcuts import render


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


def scan_view(request: HttpRequest) -> HttpResponse:
    """Display scan page.

    Args:
        request: HttpRequest object.

    Returns:
        HttpResponse object.
    """
    return render(request, 'app_scanner/scan.html')
