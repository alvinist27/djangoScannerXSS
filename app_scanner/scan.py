"""Module with defining scan classes."""

import logging
import os
from random import sample
from string import ascii_lowercase, ascii_uppercase
from typing import Any, Optional
from urllib.parse import parse_qs, urlencode, urljoin, urlparse

import requests
from aiohttp import ClientSession
from asgiref.sync import sync_to_async
from bs4 import BeautifulSoup, ResultSet, Tag
from django.shortcuts import render
from django.utils.timezone import now
from requests import Response
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
    """Base class of XSS scanner."""

    def __init__(
        self,
        target_url: str,
        xss_type: XSSVulnerabilityTypeChoices,
        user_id: int,
        is_one_page_scan: bool,
    ) -> None:
        """Initialize base parameters.

        Args:
            target_url: target site address for xss crawling.
            xss_type: XSSVulnerabilityTypeChoices instance.
            user_id: id of user created the scan task.
            is_one_page_scan: boolean variable indicating to generate a sitemap.
        """
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
    def _is_valid_url(url: str) -> bool:
        """Check whether the url is valid.

        Args:
            url: target site address for xss crawling.

        Returns:
            True if the url is valid and false if not valid.
        """
        parsed_url = urlparse(url)
        return bool(parsed_url.netloc) and bool(parsed_url.scheme)

    @staticmethod
    def _get_form_info(form: Tag) -> dict[str, Any]:
        """Get information about submitting a form.

        Args:
            form: bs object of form information about to get.

        Returns:
            Dictionary containing form information.
        """
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
    def _is_vulnerable_query_params(url: str, payload: str) -> bool:
        """Check vulnerability of url query parameters with specified payload.

        Args:
            url: target site address for xss crawling.
            payload: malicious code to send in a query parameter.

        Returns:
            True if the url is vulnerable and False if not.
        """
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

    def _get_scan_risk_level(self) -> Optional[ScanRiskLevelChoices]:
        """Get site risk level based on XSS scan results.

        Returns:
            ScanRiskLevelChoices instance.
        """
        xss_count = sum(len(category_urls) for category_urls in self.review.values())
        if not self.internal_urls:
            self.scan.status = ScanStatusChoices.error
            self.scan.save(update_fields=('status', 'date_end'))
            return None
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

    def _create_review_file(self, risk_level: ScanRiskLevelChoices) -> None:
        """Generate file with scan report.

        Args:
            risk_level: ScanRiskLevelChoices instance.
        """
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

    def _prepare_review(self) -> None:
        """Prepare results of XSS scan."""
        for xss_type, url_set in self.review.items():
            self.review[xss_type] = list(url_set)
        self.scan.date_end = now()
        self.scan.status = ScanStatusChoices.completed
        risk_level = self._get_scan_risk_level()
        if not risk_level:
            return None
        self._create_review_file(risk_level)
        self.scan.save(update_fields=('status', 'date_end', 'result'))

    def _submit_form(self, form_info: dict, payload: str) -> Response:
        """Submit form with specified payload.

        Args:
            form_info: dictionary containing form information.
            payload: malicious code to send in form body.

        Response:
            Requests Response object.
        """
        scan_url = urljoin(self.scan.target_url, form_info['action'])
        data = {}
        for form_field in form_info['fields']:
            if form_field['type'] in ('text', 'search') and form_field['name']:
                data[form_field['name']] = payload
        if form_info['method'] == 'post':
            return requests.post(scan_url, data=data)
        return requests.get(scan_url, params=data)


class AsyncScan(BaseScan):
    """XSS scan class using async methods."""

    @staticmethod
    async def _make_request(url: str) -> str:
        async with ClientSession() as session:
            async with session.get(url) as response:
                content = await response.read()
        return content.decode('utf-8')

    @sync_to_async
    def _get_payloads(self) -> list[dict]:
        return [{'body': payload.body, 'recommendation': payload.recommendation} for payload in self.payloads]

    @sync_to_async
    def _create_review_file(self, risk_level: ScanRiskLevelChoices) -> None:
        super()._create_review_file(risk_level)

    @sync_to_async
    def _prepare_review(self) -> None:
        for xss_type, url_set in self.review.items():
            self.review[xss_type] = list(url_set)
        self.scan.date_end = now()
        self.scan.status = ScanStatusChoices.completed

    @sync_to_async
    def _update_scan_result(self) -> None:
        self.scan.save(update_fields=('status', 'date_end', 'result'))

    async def run(self) -> None:
        """Run AsyncScan class scanner."""
        if self.scan.xss_type == XSSVulnerabilityTypeChoices.full:
            await self._full_scan()
        elif self.scan.xss_type == XSSVulnerabilityTypeChoices.reflected:
            await self._scan_reflected_xss()
        elif self.scan.xss_type == XSSVulnerabilityTypeChoices.stored:
            await self._scan_stored_xss()
        else:
            await self._scan_dom_based_xss()

    async def _create_sitemap(self, url: str, max_urls: int = 150) -> None:
        self.urls_count += 1
        if self.urls_count > max_urls:
            return
        links = await self._get_links(url)
        for link in links:
            await self._create_sitemap(link, max_urls=max_urls)

    async def _get_links(self, url: str) -> set[str]:
        urls = set()
        domain_name = urlparse(url).netloc
        page_content = await self._make_request(url)
        soup = BeautifulSoup(page_content, 'html.parser')
        hrefs = soup.find_all('a', href=True)
        for href in hrefs:
            parsed_href = urlparse(urljoin(url, href.text))
            href = parsed_href.geturl()
            if (
                domain_name not in href or
                not self._is_valid_url(href) or
                href in self.internal_urls or
                'http' not in parsed_href.scheme
            ):
                continue
            urls.add(href)
            self.internal_urls.add(href)
        return urls

    async def _get_page_forms(self, url: str) -> ResultSet:
        page_content = await self._make_request(url)
        page_soup = BeautifulSoup(page_content, 'html.parser')
        page_forms = page_soup.find_all('form')
        return page_forms

    async def _scan_reflected_xss(self, is_single_scan_type: Optional[bool] = True) -> None:
        logger.info(f'Started async Reflected XSS scanning of {self.scan.target_url}')
        vulnerable_urls = []
        if not self.internal_urls:
            await self._create_sitemap(self.scan.target_url)
        for url in self.internal_urls:
            scan_result = await self._scan_page_reflected_xss(url)
            if scan_result:
                vulnerable_urls.append(scan_result)
        self.review.update({ReviewScanTypes.reflected: vulnerable_urls})
        if not is_single_scan_type:
            return
        await self._prepare_review()
        await self._create_review_file(self._get_scan_risk_level())
        await self._update_scan_result()

    async def _scan_page_reflected_xss(self, url: str) -> Optional[dict]:
        page_forms = await self._get_page_forms(url)
        payloads = await self._get_payloads()
        for script in payloads:
            for form in page_forms:
                form_info = self._get_form_info(form)
                submit_form_response = self._submit_form(form_info, script['body']).content.decode()
                if script['body'] in submit_form_response or self._is_vulnerable_query_params(url, script['body']):
                    return {'url': url, 'script': script['body'], 'recommendation': script['recommendation']}
        return None

    async def _scan_stored_xss(self, is_single_scan_type: Optional[bool] = True) -> None:
        logger.info(f'Started async Stored XSS scanning of {self.scan.target_url}')
        vulnerable_urls = []
        if not self.internal_urls:
            await self._create_sitemap(self.scan.target_url)
        for url in self.internal_urls:
            scan_result = await self._scan_page_stored_xss(url)
            if scan_result:
                vulnerable_urls.append(scan_result)
        self.review.update({ReviewScanTypes.stored: vulnerable_urls})
        if not is_single_scan_type:
            return
        await self._prepare_review()
        await self._create_review_file(self._get_scan_risk_level())
        await self._update_scan_result()

    async def _test_stored_xss(self, page_forms: ResultSet) -> set:
        char_set = ascii_lowercase + ascii_uppercase
        payload_length = 20
        test_payload = ''.join(sample(char_set, payload_length))
        payload_exist_urls = set()
        for form in page_forms:
            form_info = self._get_form_info(form)
            self._submit_form(form_info, test_payload).content.decode()
            for url in self.internal_urls:
                page_content = await self._make_request(url)
                if test_payload in page_content:
                    payload_exist_urls.add(url)
        return payload_exist_urls

    async def _scan_page_stored_xss(self, url: str) -> Optional[dict]:
        page_forms = await self._get_page_forms(url)
        payload_exist_urls = await self._test_stored_xss(page_forms=page_forms)
        payloads = await self._get_payloads()
        for script in payloads:
            for form in page_forms:
                form_info = self._get_form_info(form)
                self._submit_form(form_info, script['body']).content.decode()
                scan_result = await self._check_potential_urls(url, payload_exist_urls, script)
                if scan_result:
                    return scan_result
        return None

    async def _check_potential_urls(self, url: str, payload_exist_urls: set, script: dict) -> Optional[dict]:
        for potential_url in payload_exist_urls:
            page_content = await self._make_request(potential_url)
            if script['body'] in page_content:
                return {'url': url, 'script': script['body'], 'recommendation': script['recommendation']}
        return None

    async def _scan_dom_based_xss(self, is_single_scan_type: Optional[bool] = True) -> None:
        logger.info(f'Started async DOM-Based XSS scanning of {self.scan.target_url}')
        vulnerable_urls = []
        if not self.internal_urls:
            await self._create_sitemap(self.scan.target_url)
        payloads = await self._get_payloads()
        for url in self.internal_urls:
            for script in payloads:
                target_url = f'{url}#{script["body"]}'
                page_content = await self._make_request(target_url)
                if script['body'] in page_content:
                    vulnerable_urls.append({
                        'url': url,
                        'script': script['body'],
                        'recommendation': script['recommendation'],
                    })
                    break
        self.review.update({ReviewScanTypes.dom_based: vulnerable_urls})
        if not is_single_scan_type:
            return
        await self._prepare_review()
        await self._create_review_file(self._get_scan_risk_level())
        await self._update_scan_result()

    async def _full_scan(self) -> None:
        logger.info(f'Started async Full XSS scanning of {self.scan.target_url}')
        await self._scan_reflected_xss(is_single_scan_type=False)
        await self._scan_stored_xss(is_single_scan_type=False)
        await self._scan_dom_based_xss(is_single_scan_type=False)
        await self._prepare_review()
        await self._create_review_file(self._get_scan_risk_level())
        await self._update_scan_result()


class SeleniumScan(BaseScan):
    """XSS scan class using Selenium."""

    def __init__(
        self,
        target_url: str,
        xss_type: XSSVulnerabilityTypeChoices,
        user_id: int,
        is_one_page_scan: bool
    ) -> None:
        """Initialize base parameters of SeleniumScan instance.

        Args:
            target_url: target site address for xss crawling.
            xss_type: XSSVulnerabilityTypeChoices instance.
            user_id: id of user created the scan task.
            is_one_page_scan: boolean variable indicating to generate a sitemap.
        """
        chrome_options = ChromeOptions()
        self.driver = Chrome(options=chrome_options)
        super().__init__(target_url, xss_type, user_id, is_one_page_scan)

    def run(self) -> None:
        """Run SeleniumScan class scanner."""
        if self.scan.xss_type == XSSVulnerabilityTypeChoices.full:
            self._full_scan()
        elif self.scan.xss_type == XSSVulnerabilityTypeChoices.reflected:
            self._scan_reflected_xss()
        elif self.scan.xss_type == XSSVulnerabilityTypeChoices.stored:
            self._scan_stored_xss()
        else:
            self._scan_dom_based_xss()

    def _get_links(self, url: str) -> set[str]:
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
                not self._is_valid_url(href) or
                href in self.internal_urls or
                'http' not in parsed_href.scheme
            ):
                continue
            urls.add(href)
            self.internal_urls.add(href)
        return urls

    def _create_sitemap(self, url: str, max_urls: int = 150) -> None:
        self.urls_count += 1
        if self.urls_count > max_urls:
            return
        links = self._get_links(url)
        for link in links:
            self._create_sitemap(link, max_urls=max_urls)

    def _get_page_forms(self, url: str) -> ResultSet:
        self.driver.get(url)
        page_content = BeautifulSoup(self.driver.page_source, 'html.parser')
        page_forms = page_content.find_all('form')
        return page_forms

    def _scan_reflected_xss(self, is_single_scan_type: Optional[bool] = True) -> None:
        logger.info(f'Started Reflected XSS scanning of {self.scan.target_url} by Selenium')
        vulnerable_urls = []
        if not self.internal_urls:
            self._create_sitemap(self.scan.target_url)
        for url in self.internal_urls:
            scan_result = self._scan_page_reflected_xss(url)
            if scan_result:
                vulnerable_urls.append(scan_result)
        self.review.update({ReviewScanTypes.reflected: vulnerable_urls})
        if not is_single_scan_type:
            return
        self.driver.quit()
        self._prepare_review()

    def _scan_page_reflected_xss(self, url: str) -> Optional[dict]:
        page_forms = self._get_page_forms(url)
        for script in self.payloads:
            for form in page_forms:
                form_info = self._get_form_info(form)
                submit_form_response = self._submit_form(form_info, script.body).content.decode()
                if script.body in submit_form_response or self._is_vulnerable_query_params(url, script.body):
                    return {'url': url, 'script': script.body, 'recommendation': script.recommendation}
        return None

    def _scan_stored_xss(self, is_single_scan_type: Optional[bool] = True) -> None:
        logger.info(f'Started Stored XSS scanning of {self.scan.target_url} by Selenium')
        vulnerable_urls = []
        if not self.internal_urls:
            self._create_sitemap(self.scan.target_url)
        for url in self.internal_urls:
            scan_result = self._scan_page_stored_xss(url)
            if scan_result:
                vulnerable_urls.append(scan_result)
        self.review.update({ReviewScanTypes.stored: vulnerable_urls})
        if not is_single_scan_type:
            return
        self.driver.quit()
        self._prepare_review()

    def _test_stored_xss(self, page_forms: ResultSet) -> set:
        char_set = ascii_lowercase + ascii_uppercase
        payload_length = 20
        test_payload = ''.join(sample(char_set, payload_length))
        payload_exist_urls = set()
        for form in page_forms:
            form_info = self._get_form_info(form)
            self._submit_form(form_info, test_payload).content.decode()
            for url in self.internal_urls:
                self.driver.get(url)
                if test_payload in self.driver.page_source:
                    payload_exist_urls.add(url)
        return payload_exist_urls

    def _scan_page_stored_xss(self, url: str) -> Optional[dict]:
        page_forms = self._get_page_forms(url)
        payload_exist_urls = self._test_stored_xss(page_forms=page_forms)
        for script in self.payloads:
            for form in page_forms:
                form_info = self._get_form_info(form)
                self._submit_form(form_info, script.body).content.decode()
                scan_result = self._check_potential_urls(url, payload_exist_urls, script)
                if scan_result:
                    return scan_result
        return None

    def _check_potential_urls(self, url: str, payload_exist_urls: set, script: Payload) -> Optional[dict]:
        for potential_url in payload_exist_urls:
            self.driver.get(potential_url)
            if script.body in self.driver.page_source:
                return {'url': url, 'script': script.body, 'recommendation': script.recommendation}
        return None

    def _scan_dom_based_xss(self, is_single_scan_type: Optional[bool] = True) -> None:
        logger.info(f'Started DOM-Based XSS scanning of {self.scan.target_url} by Selenium')
        vulnerable_urls = []
        if not self.internal_urls:
            self._create_sitemap(self.scan.target_url)
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
        self._prepare_review()

    def _full_scan(self) -> None:
        logger.info(f'Started Full XSS scanning of {self.scan.target_url} by Selenium')
        self._scan_reflected_xss(is_single_scan_type=False)
        self._scan_stored_xss(is_single_scan_type=False)
        self._scan_dom_based_xss(is_single_scan_type=False)
        self.driver.quit()
        self._prepare_review()
