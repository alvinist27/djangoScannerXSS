from random import sample
from string import ascii_lowercase, ascii_uppercase
from typing import Set
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from selenium.webdriver import Chrome, ChromeOptions
from selenium.webdriver.common.by import By

SCRIPTS = [
    '<script>alert("XSS")</script>',
    '"><script >alert(document.cookie)</script >',
    '"><ScRiPt>alert(document.cookie)</ScRiPt>',
    '"%3cscript%3ealert(document.cookie)%3c/script%3e',
    '<scr<script>ipt>alert(document.cookie)</script>',
]


class BrowserOptions():
    pass


class ScanProcessSelenium:
    def __init__(self, target_url: str):
        chrome_options = ChromeOptions()
        self.driver = Chrome(options=chrome_options)
        self.urls_count = 0
        self.internal_urls = set()
        self.external_urls = set()
        self.target_url = target_url

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
            if domain_name not in href:
                if href not in self.external_urls:
                    self.external_urls.add(href)
                continue
            elif self.is_valid_url(href) and href not in self.internal_urls:
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
        scan_url = urljoin(self.target_url, form_info['action'])
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
            self.create_sitemap(self.target_url)
        for url in self.internal_urls:
            page_forms = self.get_page_forms(url)
            for script in SCRIPTS:
                for form in page_forms:
                    form_info = self.get_form_info(form)
                    submit_form_response = self.submit_form(form_info, script).content.decode()
                    if script in submit_form_response:
                        vulnerable_urls.add(url)
                        break
        return vulnerable_urls

    def scan_stored_xss(self):
        vulnerable_urls = set()
        if not self.internal_urls:
            self.create_sitemap(self.target_url)
        for url in self.internal_urls:
            page_forms = self.get_page_forms(url)
            payload_exist_urls = self.test_stored_xss(page_forms=page_forms)
            for script in SCRIPTS:
                for form in page_forms:
                    form_info = self.get_form_info(form)
                    self.submit_form(form_info, script).content.decode()
                    for potential_url in payload_exist_urls:
                        self.driver.get(potential_url)
                        if script in self.driver.page_source:
                            vulnerable_urls.add(url)
                            break
        return vulnerable_urls

    def scan_dom_based_xss(self):
        vulnerable_urls = set()
        if not self.internal_urls:
            self.create_sitemap(self.target_url)
        for url in self.internal_urls:
            for script in SCRIPTS:
                target_url = f'{url}#{script}'
                self.driver.get(target_url)
                if script in self.driver.page_source:
                    vulnerable_urls.add(url)
                    break
        return vulnerable_urls


if __name__ == '__main__':
    scan = ScanProcessSelenium('http://testphp.vulnweb.com/')
    print(scan.scan_reflected_xss())
