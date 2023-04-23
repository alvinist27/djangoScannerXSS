"""URL configuration for app_users."""

from django.urls import path

from app_users import views

urlpatterns = [
    path('login/', views.UserLoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('create/', views.UserSignUpView.as_view(), name='signup'),
    # path('profile/', views, name='profile'),
    # path('history/', views, name='history'),
]