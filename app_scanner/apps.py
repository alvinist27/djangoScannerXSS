"""Module with app_scanner configs."""

from django.apps import AppConfig


class AppScannerConfig(AppConfig):
    """Configuration class for app_scanner application."""

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'app_scanner'
