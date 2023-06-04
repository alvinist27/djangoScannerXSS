"""Module with defining scan classes."""

import logging
import os
from random import sample
from string import ascii_lowercase, ascii_uppercase
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import requests
from aiohttp import ClientSession
from bs4 import BeautifulSoup
from django.shortcuts import render
from django.utils.timezone import now
from selenium.webdriver import Chrome, ChromeOptions
from selenium.webdriver.common.by import By

from app_scanner.choices import ReviewScanTypes, ScanRiskLevelChoices, ScanStatusChoices, XSSVulnerabilityTypeChoices
from app_scanner.models import Payload, Scan, ScanResult
from djangoScannerXSS.settings import REVIEW_DIR, REVIEW_DIR_NAME

logger = logging.getLogger('scanner')


class BaseAdapter(object):
    """Base adapter class."""

    def write(self, content: Any) -> Any:
        """Write data to destination.

        Args:
            content: data to be written.
        """
        pass

    def read(self) -> Any:
        """Read data from a data source."""
        pass


class FileAdapter(BaseAdapter):
    """Adapter class for i/o file operations."""

    def __init__(self, file_path: str) -> None:
        """Initialize FileAdapter object.

        Args:
            file_path: path to file for write and read operations.
        """
        self.file_path = file_path

    def write(self, content: bytes) -> None:
        """Write data to a file.

        Args:
            content: data to be written to the file.
        """
        try:
            with open(self.file_path, 'wb') as file_obj:
                file_obj.write(content)
        except FileNotFoundError as file_error:
            error_message = f'FileNotFoundError. Create folders first. Error: {file_error}'
            logger.error(error_message)

    def read(self) -> Optional[str]:
        """Read data from a file.

        Returns:
            Reading file content.
        """
        try:
            with open(self.file_path, 'r') as file_obj:
                file_content = file_obj.read()
        except FileNotFoundError as file_error:
            error_message = f'FileNotFoundError. File with specified path not exists. Error: {file_error}'
            logger.error(error_message)
            return None
        return file_content


class BaseScan:
    def __init__(self, target_url: str, xss_type: XSSVulnerabilityTypeChoices, user_id: int, is_one_page_scan: bool):
        self.urls_count = 0
        self.internal_urls: set = set()
        self.review: dict = {}
        self.is_one_page_scan = is_one_page_scan
        self.scan = Scan.objects.create(
            target_url=target_url,
            xss_type=xss_type,
            user_id=user_id,
            status=ScanStatusChoices.started,
        )
        self.payloads = Payload.objects.all()

    @staticmethod
    def is_valid_url(url: str) -> bool:
        parsed_url = urlparse(url)
        return bool(parsed_url.netloc) and bool(parsed_url.scheme)

    @staticmethod
    def get_form_info(form):
        fields = []
        for field_name in ('input', 'textarea'):
            for field in form.find_all(field_name):
                fields.append({
                    'name': field.attrs.get('name', ''),
                    'type': field.attrs.get('type', 'text'),
                })
        return {
            'fields': fields,
            'action': form.attrs.get('action', '').lower(),
            'method': form.attrs.get('method', 'get').lower(),
        }

    @staticmethod
    def is_vulnerable_query_params(url, payload):
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        if not query_params:
            return False
        modified_params = query_params.copy()
        for param_name in query_params:
            last_param_value, modified_params[param_name] = modified_params[param_name], payload
            modified_url = parsed_url._replace(query=urlencode(modified_params, doseq=True)).geturl()
            if payload in requests.get(modified_url).content.decode():
                return True
            modified_params[param_name] = last_param_value
        return False

    def get_scan_risk_level(self) -> Optional[ScanRiskLevelChoices]:
        xss_count = sum(len(category_urls) for category_urls in self.review.values())
        if not self.internal_urls:
            self.scan.status = ScanStatusChoices.error
            self.scan.save(update_fields=('status', 'date_end'))
            return
        severity = xss_count * 100 / len(self.internal_urls)
        if severity >= ScanRiskLevelChoices.high.value:
            risk_level = ScanRiskLevelChoices.high
        elif severity >= ScanRiskLevelChoices.medium.value:
            risk_level = ScanRiskLevelChoices.medium
        elif severity == ScanRiskLevelChoices.healthy.value:
            risk_level = ScanRiskLevelChoices.healthy
        else:
            risk_level = ScanRiskLevelChoices.low
        return risk_level

    def create_review_file(self, risk_level):
        review_filename = f'scan_{self.scan.id}.html'
        review_file_path = os.path.join(REVIEW_DIR, review_filename)
        self.scan.result = ScanResult.objects.create(
            risk_level=risk_level,
            review=self.review,
            review_file=os.path.join(REVIEW_DIR_NAME, review_filename),
        )
        html_output = render(None, 'app_scanner/review.html', {
            'target_url': self.scan.target_url,
            'xss_type': self.scan.get_xss_type_display(),
            'review_data': self.review,
            'risk_level': self.scan.result.get_risk_level_display(),
        })
        FileAdapter(file_path=review_file_path).write(html_output.content)

    def prepare_review_file(self):
        for xss_type, url_set in self.review.items():
            self.review[xss_type] = list(url_set)
        self.scan.date_end = now()
        self.scan.status = ScanStatusChoices.completed
        risk_level = self.get_scan_risk_level()
        self.create_review_file(risk_level)
        self.scan.save(update_fields=('status', 'date_end', 'result'))

    def submit_form(self, form_info, payload):
        scan_url = urljoin(self.scan.target_url, form_info['action'])
        data = {}
        for form_field in form_info['fields']:
            if form_field['type'] in ('text', 'search') and form_field['name']:
                data[form_field['name']] = payload
        if form_info['method'] == 'post':
            return requests.post(scan_url, data=data)
        return requests.get(scan_url, params=data)


class AsyncScan(BaseScan):
    async def run(self):
        if self.scan.xss_type == XSSVulnerabilityTypeChoices.full:
            await self.full_scan()
        elif self.scan.xss_type == XSSVulnerabilityTypeChoices.reflected:
            await self.scan_reflected_xss()
        elif self.scan.xss_type == XSSVulnerabilityTypeChoices.stored:
            await self.scan_stored_xss()
        else:
            await self.scan_dom_based_xss()

    @staticmethod
    async def make_request(url: str) -> str:
        async with ClientSession() as session:
            async with session.get(url) as response:
                content = await response.read()
        return content.decode('utf-8')

    async def create_sitemap(self, url: str, max_urls: int = 150) -> None:
        self.urls_count += 1
        if self.urls_count > max_urls:
            return
        links = await self.get_links(url)
        for link in links:
            await self.create_sitemap(link, max_urls=max_urls)

    async def get_links(self, url: str) -> set[str]:
        urls = set()
        domain_name = urlparse(url).netloc
        page_content = await self.make_request(url)
        soup = BeautifulSoup(page_content, 'html.parser')
        hrefs = soup.find_all('a', href=True)
        for href in hrefs:
            parsed_href = urlparse(urljoin(url, href))
            href = parsed_href.geturl()
            if (
                domain_name not in href or
                not self.is_valid_url(href) or
                href in self.internal_urls or
                'http' not in parsed_href.scheme
            ):
                continue
            urls.add(href)
            self.internal_urls.add(href)
        return urls

    async def get_page_forms(self, url):
        page_content = await self.make_request(url)
        page_soup = BeautifulSoup(page_content, 'html.parser')
        page_forms = page_soup.find_all('form')
        return page_forms

    async def scan_reflected_xss(self, is_single_scan_type=True):
        logger.info(f'Started async Reflected XSS scanning of {self.scan.target_url}')
        vulnerable_urls = []
        if not self.internal_urls:
            await self.create_sitemap(self.scan.target_url)
        for url in self.internal_urls:
            scan_result = await self.scan_page_reflected_xss(url)
            if scan_result:
                vulnerable_urls.append(scan_result)
        self.review.update({ReviewScanTypes.reflected: vulnerable_urls})
        if not is_single_scan_type:
            return
        self.prepare_review_file()

    async def scan_page_reflected_xss(self, url) -> Optional[dict]:
        page_forms = await self.get_page_forms(url)
        for script in self.payloads:
            for form in page_forms:
                form_info = self.get_form_info(form)
                submit_form_response = self.submit_form(form_info, script.body).content.decode()
                if script.body in submit_form_response or self.is_vulnerable_query_params(url, script.body):
                    return {'url': url, 'script': script.body, 'recommendation': script.recommendation}

    async def scan_stored_xss(self, is_single_scan_type=True):
        logger.info(f'Started async Stored XSS scanning of {self.scan.target_url}')
        vulnerable_urls = []
        if not self.internal_urls:
            await self.create_sitemap(self.scan.target_url)
        for url in self.internal_urls:
            scan_result = await self.scan_page_stored_xss(url)
            if scan_result:
                vulnerable_urls.append(scan_result)
        self.review.update({ReviewScanTypes.stored: vulnerable_urls})
        if not is_single_scan_type:
            return
        self.prepare_review_file()

    async def test_stored_xss(self, page_forms):
        char_set = ascii_lowercase + ascii_uppercase
        payload_length = 20
        test_payload = ''.join(sample(char_set, payload_length))
        payload_exist_urls = set()
        for form in page_forms:
            form_info = self.get_form_info(form)
            self.submit_form(form_info, test_payload).content.decode()
            for url in self.internal_urls:
                page_content = await self.make_request(url)
                if test_payload in page_content:
                    payload_exist_urls.add(url)
        return payload_exist_urls

    async def scan_page_stored_xss(self, url):
        page_forms = await self.get_page_forms(url)
        payload_exist_urls = await self.test_stored_xss(page_forms=page_forms)
        for script in self.payloads:
            for form in page_forms:
                form_info = self.get_form_info(form)
                self.submit_form(form_info, script.body).content.decode()
                scan_result = await self.check_potential_urls(url, payload_exist_urls, script)
                if scan_result:
                    return scan_result

    async def check_potential_urls(self, url, payload_exist_urls: set, script: Payload):
        for potential_url in payload_exist_urls:
            page_content = self.make_request(potential_url)
            if script.body in page_content:
                return {'url': url, 'script': script.body, 'recommendation': script.recommendation}

    async def scan_dom_based_xss(self, is_single_scan_type=True):
        logger.info(f'Started async DOM-Based XSS scanning of {self.scan.target_url}')
        vulnerable_urls = []
        if not self.internal_urls:
            await self.create_sitemap(self.scan.target_url)
        for url in self.internal_urls:
            for script in self.payloads:
                target_url = f'{url}#{script.body}'
                page_content = await self.make_request(target_url)
                if script.body in page_content:
                    vulnerable_urls.append({
                        'url': url,
                        'script': script.body,
                        'recommendation': script.recommendation,
                    })
                    break
        self.review.update({ReviewScanTypes.dom_based: vulnerable_urls})
        if not is_single_scan_type:
            return
        self.prepare_review_file()

    async def full_scan(self):
        logger.info(f'Started async Full XSS scanning of {self.scan.target_url}')
        await self.scan_reflected_xss(is_single_scan_type=False)
        await self.scan_stored_xss(is_single_scan_type=False)
        await self.scan_dom_based_xss(is_single_scan_type=False)
        self.prepare_review_file()


class SeleniumScan(BaseScan):

    def __init__(self, target_url: str, xss_type: XSSVulnerabilityTypeChoices, user_id: int, is_one_page_scan: bool):
        chrome_options = ChromeOptions()
        self.driver = Chrome(options=chrome_options)
        super().__init__(target_url, xss_type, user_id, is_one_page_scan)

    def run(self):
        if self.scan.xss_type == XSSVulnerabilityTypeChoices.full:
            self.full_scan()
        elif self.scan.xss_type == XSSVulnerabilityTypeChoices.reflected:
            self.scan_reflected_xss()
        elif self.scan.xss_type == XSSVulnerabilityTypeChoices.stored:
            self.scan_stored_xss()
        else:
            self.scan_dom_based_xss()

    def get_links(self, url: str) -> set[str]:
        urls = set()
        domain_name = urlparse(url).netloc
        self.driver.get(url)
        a_tags = self.driver.find_elements(By.CSS_SELECTOR, 'a')
        for a_tag in a_tags:
            href = a_tag.get_attribute('href')
            if not href:
                continue
            parsed_href = urlparse(urljoin(url, href))
            href = parsed_href.geturl()
            if (
                domain_name not in href or
                not self.is_valid_url(href) or
                href in self.internal_urls or
                'http' not in parsed_href.scheme
            ):
                continue
            urls.add(href)
            self.internal_urls.add(href)
        return urls

    def create_sitemap(self, url: str, max_urls: int = 150) -> None:
        self.urls_count += 1
        if self.urls_count > max_urls:
            return
        links = self.get_links(url)
        for link in links:
            self.create_sitemap(link, max_urls=max_urls)

    def get_page_forms(self, url):
        self.driver.get(url)
        page_content = BeautifulSoup(self.driver.page_source, 'html.parser')
        page_forms = page_content.find_all('form')
        return page_forms

    def scan_reflected_xss(self, is_single_scan_type=True):
        logger.info(f'Started Reflected XSS scanning of {self.scan.target_url} by Selenium')
        vulnerable_urls = []
        if not self.internal_urls:
            self.create_sitemap(self.scan.target_url)
        for url in self.internal_urls:
            scan_result = self.scan_page_reflected_xss(url)
            if scan_result:
                vulnerable_urls.append(scan_result)
        self.review.update({ReviewScanTypes.reflected: vulnerable_urls})
        if not is_single_scan_type:
            return
        self.driver.quit()
        self.prepare_review_file()

    def scan_page_reflected_xss(self, url):
        page_forms = self.get_page_forms(url)
        for script in self.payloads:
            for form in page_forms:
                form_info = self.get_form_info(form)
                submit_form_response = self.submit_form(form_info, script.body).content.decode()
                if script.body in submit_form_response or self.is_vulnerable_query_params(url, script.body):
                    return {'url': url, 'script': script.body, 'recommendation': script.recommendation}

    def scan_stored_xss(self, is_single_scan_type=True):
        logger.info(f'Started Stored XSS scanning of {self.scan.target_url} by Selenium')
        vulnerable_urls = []
        if not self.internal_urls:
            self.create_sitemap(self.scan.target_url)
        for url in self.internal_urls:
            scan_result = self.scan_page_stored_xss(url)
            if scan_result:
                vulnerable_urls.append(scan_result)
        self.review.update({ReviewScanTypes.stored: vulnerable_urls})
        if not is_single_scan_type:
            return
        self.driver.quit()
        self.prepare_review_file()

    def test_stored_xss(self, page_forms):
        char_set = ascii_lowercase + ascii_uppercase
        payload_length = 20
        test_payload = ''.join(sample(char_set, payload_length))
        payload_exist_urls = set()
        for form in page_forms:
            form_info = self.get_form_info(form)
            self.submit_form(form_info, test_payload).content.decode()
            for url in self.internal_urls:
                self.driver.get(url)
                if test_payload in self.driver.page_source:
                    payload_exist_urls.add(url)
        return payload_exist_urls

    def scan_page_stored_xss(self, url):
        page_forms = self.get_page_forms(url)
        payload_exist_urls = self.test_stored_xss(page_forms=page_forms)
        for script in self.payloads:
            for form in page_forms:
                form_info = self.get_form_info(form)
                self.submit_form(form_info, script.body).content.decode()
                scan_result = self.check_potential_urls(url, payload_exist_urls, script)
                if scan_result:
                    return scan_result

    def check_potential_urls(self, url, payload_exist_urls: set, script: Payload):
        for potential_url in payload_exist_urls:
            self.driver.get(potential_url)
            if script.body in self.driver.page_source:
                return {'url': url, 'script': script.body, 'recommendation': script.recommendation}

    def scan_dom_based_xss(self, is_single_scan_type=True):
        logger.info(f'Started DOM-Based XSS scanning of {self.scan.target_url} by Selenium')
        vulnerable_urls = []
        if not self.internal_urls:
            self.create_sitemap(self.scan.target_url)
        for url in self.internal_urls:
            for script in self.payloads:
                target_url = f'{url}#{script.body}'
                self.driver.get(target_url)
                if script.body in self.driver.page_source:
                    vulnerable_urls.append({'url': url, 'script': script.body, 'recommendation': script.recommendation})
                    break
        self.review.update({ReviewScanTypes.dom_based: vulnerable_urls})
        if not is_single_scan_type:
            return
        self.driver.quit()
        self.prepare_review_file()

    def full_scan(self):
        logger.info(f'Started Full XSS scanning of {self.scan.target_url} by Selenium')
        self.scan_reflected_xss(is_single_scan_type=False)
        self.scan_stored_xss(is_single_scan_type=False)
        self.scan_dom_based_xss(is_single_scan_type=False)
        self.driver.quit()
        self.prepare_review_file()
