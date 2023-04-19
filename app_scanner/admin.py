"""Admin of app_scanner application."""

from django.contrib import admin

from app_scanner.models import Payload, Scan, ScanResult, User


@admin.register(Payload)
class PayloadAdmin(admin.ModelAdmin):
    """Class for admin view for Payload objects."""

    list_display = ('id', 'body')


@admin.register(ScanResult)
class ScanResultAdmin(admin.ModelAdmin):
    """Class for admin view for ScanResult objects."""

    list_display = ('id', 'risk_level', 'review_file_path')
    list_filter = ('risk_level',)


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    """Class for admin view for Scan objects."""

    list_display = ('id', 'target_url', 'xss_type', 'date_start', 'date_end', 'status')
    list_filter = ('status', 'xss_type')


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    """Class for admin view for User objects."""

    list_display = ('id', 'username')
