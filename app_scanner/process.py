from random import sample
from string import ascii_lowercase, ascii_uppercase
from typing import Dict, Set
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from selenium.webdriver import Chrome, ChromeOptions
from selenium.webdriver.common.by import By

from app_scanner.choices import ScanStatusChoices, XSSVulnerabilityTypeChoices
from app_scanner.models import Payload, Scan


class ScanProcessSelenium:
    def __init__(self, target_url: str, xss_type: str, user_id: int):
        chrome_options = ChromeOptions()
        self.driver = Chrome(options=chrome_options)
        self.urls_count = 0
        self.internal_urls: Set = set()
        self.review: Dict = {}
        self.scan = Scan.objects.create(
            target_url=target_url,
            xss_type=xss_type,
            user_id=user_id,
            status=ScanStatusChoices.started,
        )

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

    def get_links(self, url: str) -> Set[str]:
        urls = set()
        domain_name = urlparse(url).netloc
        self.driver.get(url)
        a_tags = self.driver.find_elements(By.CSS_SELECTOR, 'a')
        for a_tag in a_tags:
            href = a_tag.get_attribute('href')
            if not href:
                continue
            parsed_href = urlparse(urljoin(url, href))
            href = f'{parsed_href.scheme}://{parsed_href.netloc}{parsed_href.path}'
            if domain_name not in href and not self.is_valid_url(href) and href in self.internal_urls:
                continue
            urls.add(href)
            self.internal_urls.add(href)
        return urls

    def create_sitemap(self, url: str, max_urls: int = 20) -> None:
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

    def get_page_inputs(self, url):
        self.driver.get(url)
        page_content = BeautifulSoup(self.driver.page_source, 'html.parser')
        return page_content.find_all('form')

    def submit_form(self, form_info, payload):
        scan_url = urljoin(self.scan.target_url, form_info['action'])
        data = {}
        for form_field in form_info['fields']:
            if form_field['type'] in ('text', 'search') and form_field['name']:
                data[form_field['name']] = payload
        if form_info['method'] == 'post':
            return requests.post(scan_url, data=data)
        return requests.get(scan_url, params=data)

    def test_stored_xss(self, page_forms):
        char_set = ascii_lowercase + ascii_uppercase
        payload_length = 20
        test_payload = ''.join(sample(char_set, payload_length))

        payload_exist_urls = set()
        for form in page_forms:
            form_info = self.get_form_info(form)
            form_response = self.submit_form(form_info, test_payload).content.decode()
            for url in self.internal_urls:
                self.driver.get(url)
                if test_payload in form_response:
                    payload_exist_urls.add(url)
        return payload_exist_urls

    def scan_reflected_xss(self):
        vulnerable_urls = set()
        if not self.internal_urls:
            self.create_sitemap(self.scan.target_url)
        for url in self.internal_urls:
            page_forms = self.get_page_forms(url)
            for script in Payload.objects.all():
                for form in page_forms:
                    form_info = self.get_form_info(form)
                    submit_form_response = self.submit_form(form_info, script.body).content.decode()
                    if script.body in submit_form_response:
                        vulnerable_urls.add(url)
                        break
        self.review.update({'reflected': vulnerable_urls})
        return self.review

    def scan_stored_xss(self):
        vulnerable_urls = set()
        if not self.internal_urls:
            self.create_sitemap(self.scan.target_url)
        for url in self.internal_urls:
            page_forms = self.get_page_forms(url)
            payload_exist_urls = self.test_stored_xss(page_forms=page_forms)
            for script in Payload.objects.all():
                for form in page_forms:
                    form_info = self.get_form_info(form)
                    self.submit_form(form_info, script.body).content.decode()
                    for potential_url in payload_exist_urls:
                        self.driver.get(potential_url)
                        if script.body in self.driver.page_source:
                            vulnerable_urls.add(url)
                            break
        self.review.update({'stored': vulnerable_urls})
        return self.review

    def scan_dom_based_xss(self):
        vulnerable_urls = set()
        if not self.internal_urls:
            self.create_sitemap(self.scan.target_url)
        for url in self.internal_urls:
            for script in Payload.objects.all():
                target_url = f'{url}#{script}'
                self.driver.get(target_url)
                if script.body in self.driver.page_source:
                    vulnerable_urls.add(url)
                    break
        self.review.update({'DOM-based': vulnerable_urls})
        return self.review

    def full_scan(self):
        self.scan_reflected_xss()
        self.scan_stored_xss()
        self.scan_dom_based_xss()


if __name__ == '__main__':
    DB_USER_ID = 1
    scan = ScanProcessSelenium(
        target_url='http://testphp.vulnweb.com/',
        xss_type=XSSVulnerabilityTypeChoices.reflected[0],
        user_id=DB_USER_ID,
    )
    print(scan.scan_reflected_xss())
