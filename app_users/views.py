"""Module for app_users views."""

from django.contrib.auth import get_user_model
from django.contrib.auth.views import LoginView, LogoutView
from django.views.generic import CreateView

from app_users.forms import UserSignUpForm

User = get_user_model()


class UserLoginView(LoginView):
    """LoginView class for user login."""

    template_name = 'app_users/login.html'


class UserLogoutView(LogoutView):
    """LogoutView class for user logout."""

    next_page = '/'


class UserSignUpView(CreateView):
    """CreateView class for user SignUp."""

    form_class = UserSignUpForm
    success_url = '/'
    template_name = 'app_users/signup.html'


class UserProfileView(LogoutView):
    pass
