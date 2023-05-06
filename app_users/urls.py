"""URL configuration for app_users."""

from django.urls import path

from app_users import views

urlpatterns = [
    path('login/', views.UserLoginView.as_view(), name='login'),
    path('logout/', views.UserLogoutView.as_view(), name='logout'),
    path('signup/', views.UserSignUpView.as_view(), name='signup'),
    path('profile/', views.ProfileScanListView.as_view(), name='profile'),
    path('scan/<int:pk>', views.ScanDetailView.as_view(), name='scan'),
]