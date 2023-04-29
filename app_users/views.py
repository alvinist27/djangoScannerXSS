"""Module for app_users views."""

from django.contrib.auth import get_user_model
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView, LogoutView
from django.views.generic import CreateView, DetailView, ListView

from app_scanner.models import Scan
from app_users.forms import UserSignUpForm

User = get_user_model()


class UserLoginView(LoginView):
    """LoginView class for user login."""

    template_name = 'app_users/login.html'


class UserLogoutView(LoginRequiredMixin, LogoutView):
    """LogoutView class for user logout."""

    next_page = '/'


class UserSignUpView(CreateView):
    """CreateView class for user SignUp."""

    form_class = UserSignUpForm
    success_url = '/'
    template_name = 'app_users/signup.html'


class ProfileScanListView(LoginRequiredMixin, ListView):
    """ListView class for user scans history."""

    model = Scan
    context_object_name = 'user_scans'
    paginate_by = 10
    template_name = 'app_users/profile.html'

    def get_queryset(self):
        return Scan.objects.filter(user_id=self.request.user.id)


class ScanDetailView(LoginRequiredMixin, DetailView):
    """DetailView class for scan object."""

    model = Scan
    context_object_name = 'scan'
    template_name = 'app_users/scan.html'
