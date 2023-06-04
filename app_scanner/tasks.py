"""Module with defining celery tasks."""

import asyncio

from celery import Task

from app_scanner.choices import XSSVulnerabilityTypeChoices
from app_scanner.scan import AsyncScan, SeleniumScan
from djangoScannerXSS import celery_app


class ScanProcess(Task):
    name = 'ScanProcess'

    @staticmethod
    def run(**kwargs):
        asyncio.run(AsyncScan(**kwargs).run())


class ScanProcessSelenium(Task):
    name = 'ScanProcessSelenium'

    @staticmethod
    def run(**kwargs):
        SeleniumScan(**kwargs).run()


if __name__ == '__main__':
    DB_USER_ID = 1
    task = ScanProcessSelenium()
    task.delay(
        target_url='http://testphp.vulnweb.com/',
        xss_type=XSSVulnerabilityTypeChoices.reflected[0],
        user_id=DB_USER_ID,
        is_cloudflare=False,
        is_one_page_scan=False,
    )

celery_app.register_task(ScanProcess)
celery_app.register_task(ScanProcessSelenium)
