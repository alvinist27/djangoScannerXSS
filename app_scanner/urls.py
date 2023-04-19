"""URL configuration for app_scanner."""

from django.urls import path

from app_scanner import views

urlpatterns = [
    path('', views.main_view, name='main'),
    path('about/', views.about_view, name='about'),
    path('contact/', views.contact_view, name='contact'),
    path('404/', views.not_found, name='not_found'),
    path('project/', views.project_view, name='project'),
    path('service/', views.service_view, name='service'),
    path('team/', views.team_view, name='team'),
    path('testimonial/', views.testimonial_view, name='testimonial'),
    path('scan/', views.ContactFormView.as_view(), name='scan'),
]