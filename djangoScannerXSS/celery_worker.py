"""Module with defining an instance of the celery worker."""

from djangoScannerXSS import celery_app

celery_app.start(['-A', 'djangoScannerXSS', 'worker', '-l', 'INFO'])
