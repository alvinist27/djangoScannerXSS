"""Module with defining an instance of the celery library."""

from __future__ import absolute_import

import os

from celery import Celery

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'djangoScannerXSS.settings')

celery_app = Celery('djangoScannerXSS')
celery_app.config_from_object('django.conf:settings', namespace='CELERY')
celery_app.autodiscover_tasks()
