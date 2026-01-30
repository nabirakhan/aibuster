import json
import requests
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, Empty
from urllib3.exceptions import InsecureRequestWarning
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import random
import logging

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RATE_LIMITED = "rate_limited"

@dataclass
class ScanRequest:
    path: str
    method: str = "GET"
    retries: int = 0
    status: ScanStatus = ScanStatus.PENDING
    response_time: float = 0.0
    last_try: float = 0.0

class RateLimiter:
    def __init__(self, requests_per_minute=None, requests_per_second=None):
        self.requests_per_minute = requests_per_minute
        self.requests_per_second = requests_per_second
        self.minute_window = []
        self.second_window = []
        self.lock = threading.Lock()
        if requests_per_minute:
            self.minute_limit = requests_per_minute
            self.minute_window_size = 60
        if requests_per_second:
            self.second_limit = requests_per_second
            self.second_window_size = 1
    
    def acquire(self):
        with self.lock:
            now = time.time()
            if self.requests_per_minute:
                self.minute_window = [t for t in self.minute_window if now - t < self.minute_window_size]
                if len(self.minute_window) >= self.minute_limit:
                    return False
            if self.requests_per_second:
                self.second_window = [t for t in self.second_window if now - t < self.second_window_size]
                if len(self.second_window) >= self.second_limit:
                    return False
            if self.requests_per_minute:
                self.minute_window.append(now)
            if self.requests_per_second:
                self.second_window.append(now)
            return True
    
    def wait(self):
        while not self.acquire():
            time.sleep(0.1)

class PathBuster:
    def __init__(self, base_url, threads=10, timeout=5, delay=0, retries=2, proxy=None, cookies=None, 
                 rate_limit=None, user_agent=None, headers=None, verify_ssl=False):
        self.base_url = base_url.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.retries = retries
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        default_headers = {
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        if headers:
            if isinstance(headers, str):
                try:
                    headers = json.loads(headers)
                except:
                    headers = {}
            default_headers.update(headers)
        self.session.headers.update(default_headers)
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        if cookies:
            if isinstance(cookies, str):
                cookies = self._parse_cookies(cookies)
            for name, value in cookies.items():
                self.session.cookies.set(name, value)
        self.rate_limiter = None
        if rate_limit:
            if rate_limit >= 1:
                self.rate_limiter = RateLimiter(requests_per_second=rate_limit)
            else:
                self.rate_limiter = RateLimiter(requests_per_minute=int(60 / rate_limit))
        self.stats = {'total_requests': 0, 'successful_requests': 0, 'failed_requests': 0, 
                     'rate_limited_requests': 0, 'total_response_time': 0, 'average_response_time': 0}
        self.lock = threading.Lock()
        self.request_queue = Queue()
        self.results = {'found': [], 'redirects': [], 'forbidden': [], 'unauthorized': [], 'errors': [], 'rate_limited': []}
        self.logger = logging.getLogger(__name__)
    
    def _parse_cookies(self, cookie_string):
        cookies = {}
        for cookie in cookie_string.split(';'):
            if '=' in cookie:
                name, value = cookie.strip().split('=', 1)
                cookies[name] = value
        return cookies
    
    def bust(self, paths, output):
        total_paths = len(paths)
        output.create_progress_bar(total_paths, "Testing paths")
        scan_requests = [ScanRequest(path=path) for path in paths]
        for req in scan_requests:
            self.request_queue.put(req)
        def worker():
            while True:
                try:
                    req = self.request_queue.get_nowait()
                except Empty:
                    break
                self._process_request(req, output)
                self.request_queue.task_done()
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(worker) for _ in range(self.threads)]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.logger.error(f"Worker error: {e}")
        output.complete_progress()
        if self.stats['successful_requests'] > 0:
            self.stats['average_response_time'] = self.stats['total_response_time'] / self.stats['successful_requests']
        return {'results': self.results, 'statistics': self.stats, 'target_url': self.base_url, 'total_paths_tested': total_paths}
    
    def _process_request(self, req, output):
        for attempt in range(self.retries + 1):
            try:
                if self.rate_limiter:
                    self.rate_limiter.wait()
                if self.delay > 0:
                    time.sleep(self.delay)
                with self.lock:
                    self.stats['total_requests'] += 1
                start_time = time.time()
                response = self.session.get(self.base_url + req.path, timeout=self.timeout, allow_redirects=False, verify=self.verify_ssl)
                response_time = time.time() - start_time
                with self.lock:
                    self.stats['successful_requests'] += 1
                    self.stats['total_response_time'] += response_time
                req.status = ScanStatus.COMPLETED
                req.response_time = response_time
                self._process_response(req.path, response, response_time, output)
                break
            except requests.exceptions.Timeout:
                req.status = ScanStatus.FAILED
                if attempt >= self.retries:
                    with self.lock:
                        self.stats['failed_requests'] += 1
                        self.results['errors'].append({'path': req.path, 'error': 'Timeout'})
                break
            except requests.exceptions.TooManyRedirects:
                req.status = ScanStatus.FAILED
                if attempt >= self.retries:
                    with self.lock:
                        self.stats['failed_requests'] += 1
                        self.results['errors'].append({'path': req.path, 'error': 'Too many redirects'})
                break
            except Exception as e:
                req.status = ScanStatus.FAILED
                with self.lock:
                    self.stats['failed_requests'] += 1
                if attempt >= self.retries:
                    self.results['errors'].append({'path': req.path, 'error': str(e)})
                break
        output.update_progress(self.stats['total_requests'])
    
    def _process_response(self, path, response, response_time, output):
        result = {'path': path, 'status': response.status_code, 'size': len(response.content), 'response_time': response_time,
                 'url': self.base_url + path, 'headers': dict(response.headers), 'cookies': dict(response.cookies),
                 'content_type': response.headers.get('Content-Type', ''), 'server': response.headers.get('Server', '')}
        if 'text/html' in result['content_type']:
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')
                if soup.title and soup.title.string:
                    result['title'] = soup.title.string.strip()
            except:
                pass
        if response.status_code == 200:
            self.results['found'].append(result)
            output.found(path, response.status_code, len(response.content), response_time, result['content_type'])
        elif response.status_code in [301, 302, 307, 308]:
            result['redirect_location'] = response.headers.get('Location', '')
            self.results['redirects'].append(result)
            output.found(path, response.status_code, len(response.content), response_time, result['content_type'])
        elif response.status_code == 403:
            self.results['forbidden'].append(result)
            output.found(path, response.status_code, len(response.content), response_time, result['content_type'])
        elif response.status_code == 401:
            self.results['unauthorized'].append(result)
            output.found(path, response.status_code, len(response.content), response_time, result['content_type'])
        interesting_headers = ['X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version', 'X-Debug-Token', 'X-Generator']
        for header in interesting_headers:
            if header in response.headers:
                result[header.lower()] = response.headers[header]
    
    def get_statistics(self):
        return self.stats