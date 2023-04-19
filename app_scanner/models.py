"""Module for app_shop models."""

from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.contrib.auth.models import PermissionsMixin
from django.db import models
from django.utils.translation import gettext_lazy as _

from app_scanner.choices import ScanRiskLevelChoices, ScanStatusChoices, XSSVulnerabilityTypeChoices
from djangoScannerXSS.settings import REVIEW_DIR

DB_MAX_LENGTH = 255
DB_LONG_MAX_LENGTH = 512


class CustomUserManager(BaseUserManager):
    """Custom user model manager where email is the unique auth identifier."""

    def create_user(self, username: str, password: str, **extra_fields):
        """Create and save a User with the given email and password."""
        if not username:
            raise ValueError(_('The Email must be set'))
        username = self.normalize_email(username)
        user = self.model(username=username, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, username: str, password: str, **extra_fields):
        """Create and save a SuperUser with the given email and password."""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError(_('Superuser must have is_staff=True.'))
        if extra_fields.get('is_superuser') is not True:
            raise ValueError(_('Superuser must have is_superuser=True.'))
        return self.create_user(username, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """Custom User model."""

    username = models.EmailField(max_length=DB_MAX_LENGTH, unique=True, verbose_name=_('Email'))
    date_joined = models.DateTimeField(auto_now_add=True, verbose_name=_('Date create'))
    is_staff = models.BooleanField(default=False, verbose_name=_('Is staff'))
    is_active = models.BooleanField(default=True, verbose_name=_('Is active'))

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    class Meta:
        """Class with meta information of User model."""

        verbose_name = _('User')
        verbose_name_plural = _('Users')

    def __str__(self) -> str:
        """Return string representation of the User model.

        Returns:
            Email of the User object.
        """
        return self.username


class ScanResult(models.Model):
    """Model for ScanResult entities."""

    risk_level = models.CharField(
        choices=ScanRiskLevelChoices.choices,
        verbose_name=_('Risk level'),
    )
    review = models.JSONField(verbose_name=_('Review'))
    review_file_path = models.FilePathField(path=REVIEW_DIR, blank=True, verbose_name=_('File review'))

    class Meta:
        """Class with meta information of ScanResult model."""

        verbose_name = _('Scan result')
        verbose_name_plural = _('Scan results')

    def __str__(self) -> str:
        """Return string representation of the ScanResult model.

        Returns:
            ID of the ScanResult object.
        """
        return str(self.id)


class Scan(models.Model):
    """Model for Scan entities."""

    target_url = models.URLField(max_length=DB_LONG_MAX_LENGTH, verbose_name=_('Target url'))
    xss_type = models.CharField(choices=XSSVulnerabilityTypeChoices.choices, verbose_name=_('XSS type'))
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_scans', verbose_name=_('User'))
    date_start = models.DateTimeField(auto_now_add=True, verbose_name=_('Date start'))
    date_end = models.DateTimeField(null=True, blank=True, verbose_name=_('Date end'))
    status = models.CharField(choices=ScanStatusChoices.choices, verbose_name=_('Status'))
    result = models.OneToOneField(ScanResult, on_delete=models.CASCADE, null=True, blank=True, verbose_name=_('Result'))

    class Meta:
        """Class with meta information of Scan model."""

        verbose_name = _('Scan')
        verbose_name_plural = _('Scans')

    def __str__(self) -> str:
        """Return string representation of the Scan model.

        Returns:
            ID of the Scan object.
        """
        return str(self.id)


class Payload(models.Model):
    """Model for Payload entities."""

    body = models.TextField(verbose_name=_('Body'))
    recommendation = models.TextField(blank=True, verbose_name=_('Recommendation'))

    class Meta:
        """Class with meta information of Payload model."""

        verbose_name = _('Payload')
        verbose_name_plural = _('Payloads')

    def __str__(self) -> str:
        """Return string representation of the Payload model.

        Returns:
            ID of the Payload object.
        """
        return str(self.id)
