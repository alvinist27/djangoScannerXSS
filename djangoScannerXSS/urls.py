"""URL configuration for djangoScannerXSS project."""

from django.contrib import admin
from django.urls import include, path

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('app_scanner.urls')),
    path('users/', include('app_users.urls')),
]

handler404 = "app_scanner.views.not_found"
