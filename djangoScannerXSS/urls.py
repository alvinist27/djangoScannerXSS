"""URL configuration for djangoScannerXSS project."""

from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

from djangoScannerXSS.settings import MEDIA_ROOT, MEDIA_URL

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('app_scanner.urls')),
    path('users/', include('app_users.urls')),
] + static(MEDIA_URL, document_root=MEDIA_ROOT)

handler404 = "app_scanner.views.not_found"
