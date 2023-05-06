"""URL configuration for app_scanner."""

from django.urls import path

from app_scanner import views

urlpatterns = [
    path('', views.main_view, name='main'),
    path('about/', views.about_view, name='about'),
    path('404/', views.not_found, name='not_found'),
    path('scan/', views.ScanFormView.as_view(), name='scan'),
]
