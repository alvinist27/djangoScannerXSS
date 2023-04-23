"""Module with app_users forms."""

from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm

User = get_user_model()


class UserSignUpForm(UserCreationForm):
    """Form for user creation."""

    class Meta:
        """Class with meta information of SignUpForm."""

        model = User
        fields = ('username', 'password1', 'password2')
