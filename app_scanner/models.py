"""Module for app_shop models."""

from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import PermissionsMixin
from django.db import models
from django.utils.translation import gettext_lazy as _

from app_scanner.choices import ScanRiskLevelChoices, ScanStatusChoices, XSSVulnerabilityTypeChoices
from djangoScannerXSS.settings import REVIEW_DIR

DB_SHORT_MAX_LENGTH = 1
DB_MAX_LENGTH = 255
DB_LONG_MAX_LENGTH = 512


class User(AbstractBaseUser, PermissionsMixin):
    """Custom User model."""

    email = models.EmailField(max_length=DB_MAX_LENGTH, unique=True, verbose_name=_('Email'))
    date_create = models.DateTimeField(auto_now_add=True, verbose_name=_('Date create'))

    USERNAME_FIELD = 'email'

    class Meta:
        """Class with meta information of User model."""

        verbose_name = _('User')
        verbose_name_plural = _('Users')

    def __str__(self) -> str:
        """Return string representation of the User model.

        Returns:
            Email of the User object.
        """
        return self.email


class ScanResult(models.Model):
    """Model for ScanResult entities."""

    risk_level = models.CharField(
        max_length=DB_SHORT_MAX_LENGTH,
        choices=ScanRiskLevelChoices.choices,
        verbose_name=_('Risk level'),
    )
    review = models.JSONField(verbose_name=_('Review'))
    review_file_path = models.FilePathField(path=REVIEW_DIR, verbose_name=_('Review'))

    class Meta:
        """Class with meta information of ScanResult model."""

        verbose_name = _('Scan result')
        verbose_name_plural = _('Scan results')

    def __str__(self) -> int:
        """Return string representation of the ScanResult model.

        Returns:
            ID of the ScanResult object.
        """
        return self.id


class Scan(models.Model):
    """Model for Scan entities."""

    target_url = models.URLField(max_length=DB_LONG_MAX_LENGTH, verbose_name=_('Target url'))
    xss_type = models.CharField(choices=XSSVulnerabilityTypeChoices.choices, verbose_name=_('XSS type'))
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_scans', verbose_name=_('User'))
    date_start = models.DateTimeField(auto_now_add=True, verbose_name=_('Date start'))
    date_end = models.DateTimeField(null=True, blank=True, verbose_name=_('Date end'))
    status = models.IntegerField(choices=ScanStatusChoices.choices, verbose_name=_('Status'))
    result = models.OneToOneField(ScanResult, on_delete=models.CASCADE, null=True, verbose_name=_('Result'))

    class Meta:
        """Class with meta information of Scan model."""

        verbose_name = _('Scan')
        verbose_name_plural = _('Scans')

    def __str__(self) -> int:
        """Return string representation of the Scan model.

        Returns:
            ID of the Scan object.
        """
        return self.id


class Payload(models.Model):
    """Model for Payload entities."""

    body = models.TextField(verbose_name=_('Body'))
    recommendation = models.TextField(blank=True, verbose_name=_('Recommendation'))

    class Meta:
        """Class with meta information of Payload model."""

        verbose_name = _('Payload')
        verbose_name_plural = _('Payloads')

    def __str__(self) -> int:
        """Return string representation of the Payload model.

        Returns:
            ID of the Payload object.
        """
        return self.id
