"""Admin of app_scanner application."""

from django.contrib import admin

from app_scanner.models import Payload, User, Scan, ScanResult


@admin.register(Payload)
class PayloadAdmin(admin.ModelAdmin):
    list_display = ('id', 'body')


# class ScanResultInline(admin.TabularInline):
#     model = ScanResult
#     extra = 1


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    # inlines = (ScanResultInline,)
    list_display = ('id', 'target_url', 'xss_type', 'date_start', 'date_end', 'status')


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('id', 'username')
