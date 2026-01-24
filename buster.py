"""
Enhanced path busting module with rate limiting and advanced features
"""
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

# Suppress SSL warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RATE_LIMITED = "rate_limited"

@dataclass
class ScanRequest:
    """Data class for scan requests"""
    path: str
    method: str = "GET"
    retries: int = 0
    status: ScanStatus = ScanStatus.PENDING
    response_time: float = 0.0
    last_try: float = 0.0

class RateLimiter:
    """Rate limiter for controlling request frequency"""
    
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
        """Acquire permission to make a request"""
        with self.lock:
            now = time.time()
            
            # Clean old entries
            if self.requests_per_minute:
                self.minute_window = [t for t in self.minute_window 
                                     if now - t < self.minute_window_size]
                if len(self.minute_window) >= self.minute_limit:
                    return False
            
            if self.requests_per_second:
                self.second_window = [t for t in self.second_window 
                                     if now - t < self.second_window_size]
                if len(self.second_window) >= self.second_limit:
                    return False
            
            # Add current request
            if self.requests_per_minute:
                self.minute_window.append(now)
            if self.requests_per_second:
                self.second_window.append(now)
            
            return True
    
    def wait(self):
        """Wait until a request can be made"""
        while not self.acquire():
            time.sleep(0.1)

class PathBuster:
    """Enhanced path buster with rate limiting and advanced features"""
    
    def __init__(self, base_url, threads=10, timeout=5, delay=0, 
                 retries=2, proxy=None, cookies=None, rate_limit=None,
                 user_agent=None, headers=None, verify_ssl=False):
        
        self.base_url = base_url.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.delay = delay
        self.retries = retries
        self.verify_ssl = verify_ssl
        
        # Initialize session
        self.session = requests.Session()
        
        # Configure headers
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
        
        # Configure proxy
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
        
        # Configure cookies
        if cookies:
            if isinstance(cookies, str):
                cookies = self._parse_cookies(cookies)
            for name, value in cookies.items():
                self.session.cookies.set(name, value)
        
        # Rate limiter
        self.rate_limiter = None
        if rate_limit:
            if rate_limit >= 1:
                self.rate_limiter = RateLimiter(requests_per_second=rate_limit)
            else:
                self.rate_limiter = RateLimiter(requests_per_minute=int(60 / rate_limit))
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'rate_limited_requests': 0,
            'total_response_time': 0,
            'average_response_time': 0
        }
        
        # Thread safety
        self.lock = threading.Lock()
        self.request_queue = Queue()
        self.results = {
            'found': [],
            'redirects': [],
            'forbidden': [],
            'unauthorized': [],
            'errors': [],
            'rate_limited': []
        }
        
        # Logging
        self.logger = logging.getLogger(__name__)
    
    def _parse_cookies(self, cookie_string):
        """Parse cookie string into dictionary"""
        cookies = {}
        for cookie in cookie_string.split(';'):
            if '=' in cookie:
                name, value = cookie.strip().split('=', 1)
                cookies[name] = value
        return cookies
    
    def bust(self, paths, output):
        """Enhanced busting with better threading and error handling"""
        
        total_paths = len(paths)
        output.create_progress_bar(total_paths, "Testing paths")
        
        # Create scan requests
        scan_requests = [ScanRequest(path=path) for path in paths]
        
        # Create request queue
        for req in scan_requests:
            self.request_queue.put(req)
        
        # Worker function
        def worker():
            while True:
                try:
                    req = self.request_queue.get_nowait()
                except Empty:
                    break
                
                self._process_request(req, output)
                self.request_queue.task_done()
        
        # Start workers
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(worker) for _ in range(self.threads)]
            
            # Wait for completion
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    self.logger.error(f"Worker error: {e}")
        
        # Complete progress bar
        output.complete_progress()
        
        # Calculate statistics
        if self.stats['successful_requests'] > 0:
            self.stats['average_response_time'] = (
                self.stats['total_response_time'] / self.stats['successful_requests']
            )
        
        return {
            'results': self.results,
            'statistics': self.stats,
            'target_url': self.base_url,
            'total_paths_tested': total_paths
        }
    
    def _process_request(self, req, output):
        """Process a single scan request"""
        
        # Apply rate limiting
        if self.rate_limiter:
            self.rate_limiter.wait()
        
        # Apply delay if specified
        if self.delay > 0:
            time.sleep(self.delay + random.uniform(-0.1, 0.1))  # Add jitter
        
        # Try request with retries
        for attempt in range(self.retries + 1):
            try:
                req.status = ScanStatus.RUNNING
                req.last_try = time.time()
                
                # Make request
                start_time = time.time()
                response = self.session.get(
                    self.base_url + req.path,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=self.verify_ssl
                )
                response_time = time.time() - start_time
                
                # Update statistics
                with self.lock:
                    self.stats['total_requests'] += 1
                    self.stats['successful_requests'] += 1
                    self.stats['total_response_time'] += response_time
                
                # Process response
                self._process_response(req.path, response, response_time, output)
                
                req.status = ScanStatus.COMPLETED
                req.response_time = response_time
                break
                
            except requests.exceptions.Timeout:
                req.status = ScanStatus.FAILED
                with self.lock:
                    self.stats['failed_requests'] += 1
                
                if attempt < self.retries:
                    time.sleep(1)  # Wait before retry
                else:
                    self.results['errors'].append({
                        'path': req.path,
                        'error': 'Timeout'
                    })
                    
            except requests.exceptions.ConnectionError:
                req.status = ScanStatus.FAILED
                with self.lock:
                    self.stats['failed_requests'] += 1
                
                if attempt < self.retries:
                    time.sleep(2)
                else:
                    self.results['errors'].append({
                        'path': req.path,
                        'error': 'Connection error'
                    })
                    
            except requests.exceptions.TooManyRedirects:
                self.results['redirects'].append({
                    'path': req.path,
                    'status': 302,
                    'size': 0,
                    'url': self.base_url + req.path,
                    'error': 'Too many redirects'
                })
                break
                
            except Exception as e:
                req.status = ScanStatus.FAILED
                with self.lock:
                    self.stats['failed_requests'] += 1
                
                if attempt >= self.retries:
                    self.results['errors'].append({
                        'path': req.path,
                        'error': str(e)
                    })
                break
        
        # Update progress
        output.update_progress(self.stats['total_requests'])
    
    def _process_response(self, path, response, response_time, output):
        """Process HTTP response"""
        
        result = {
            'path': path,
            'status': response.status_code,
            'size': len(response.content),
            'response_time': response_time,
            'url': self.base_url + path,
            'headers': dict(response.headers),
            'cookies': dict(response.cookies),
            'content_type': response.headers.get('Content-Type', ''),
            'server': response.headers.get('Server', '')
        }
        
        # Extract page title if HTML
        if 'text/html' in result['content_type']:
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')
                if soup.title and soup.title.string:
                    result['title'] = soup.title.string.strip()
            except:
                pass
        
        # Categorize result
        if response.status_code == 200:
            self.results['found'].append(result)
            output.found(
                path, 
                response.status_code, 
                len(response.content),
                response_time,
                result['content_type']
            )
            
        elif response.status_code in [301, 302, 307, 308]:
            result['redirect_location'] = response.headers.get('Location', '')
            self.results['redirects'].append(result)
            output.found(
                path,
                response.status_code,
                len(response.content),
                response_time,
                result['content_type']
            )
            
        elif response.status_code == 403:
            self.results['forbidden'].append(result)
            output.found(
                path,
                response.status_code,
                len(response.content),
                response_time,
                result['content_type']
            )
            
        elif response.status_code == 401:
            self.results['unauthorized'].append(result)
            output.found(
                path,
                response.status_code,
                len(response.content),
                response_time,
                result['content_type']
            )
        
        # Check for interesting headers
        interesting_headers = [
            'X-Powered-By',
            'X-AspNet-Version',
            'X-AspNetMvc-Version',
            'X-Debug-Token',
            'X-Generator'
        ]
        
        for header in interesting_headers:
            if header in response.headers:
                result[header.lower()] = response.headers[header]
    
    def bust_single(self, path):
        """Test a single path (for manual testing)"""
        try:
            start_time = time.time()
            response = self.session.get(
                self.base_url + path,
                timeout=self.timeout,
                allow_redirects=False,
                verify=self.verify_ssl
            )
            response_time = time.time() - start_time
            
            return {
                'path': path,
                'status': response.status_code,
                'size': len(response.content),
                'response_time': response_time,
                'url': self.base_url + path,
                'headers': dict(response.headers)
            }
            
        except Exception as e:
            return {
                'path': path,
                'error': str(e)
            }
    
    def get_statistics(self):
        """Get scanning statistics"""
        return self.stats
    
    def reset_statistics(self):
        """Reset statistics"""
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'rate_limited_requests': 0,
            'total_response_time': 0,
            'average_response_time': 0
        }

# Advanced scanning modes
class SmartBuster(PathBuster):
    """Smart buster with adaptive scanning"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.learned_paths = set()
        self.common_extensions = ['.php', '.html', '.txt', '.json', '.xml']
    
    def bust_with_learning(self, paths, output):
        """Bust with machine learning"""
        # Sort paths by likelihood
        sorted_paths = self._sort_by_likelihood(paths)
        
        # Run scan
        results = super().bust(sorted_paths, output)
        
        # Learn from results
        self._learn_from_results(results)
        
        return results
    
    def _sort_by_likelihood(self, paths):
        """Sort paths by estimated likelihood"""
        # Simple heuristic: prioritize shorter paths and common patterns
        def path_score(path):
            score = 0
            
            # Shorter paths are more likely
            score += 100 / (len(path) + 1)
            
            # Common patterns
            common_patterns = ['admin', 'login', 'api', 'test', 'debug']
            for pattern in common_patterns:
                if pattern in path.lower():
                    score += 50
            
            # File extensions
            for ext in self.common_extensions:
                if path.endswith(ext):
                    score += 30
            
            return score
        
        return sorted(paths, key=path_score, reverse=True)
    
    def _learn_from_results(self, results):
        """Learn from scan results to improve future scans"""
        found_paths = [r['path'] for r in results['results']['found']]
        
        # Extract patterns from found paths
        for path in found_paths:
            self.learned_paths.add(path)
            
            # Extract directory structure
            dirs = path.strip('/').split('/')
            for i in range(1, len(dirs)):
                parent_dir = '/' + '/'.join(dirs[:i]) + '/'
                self.learned_paths.add(parent_dir)

class StealthBuster(PathBuster):
    """Stealth buster for avoiding detection"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.request_jitter = kwargs.get('jitter', 0.5)
        self.random_delays = kwargs.get('random_delays', True)
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Googlebot/2.1 (+http://www.google.com/bot.html)',
            'Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)'
        ]
    
    def _process_request(self, req, output):
        """Process request with stealth techniques"""
        
        # Rotate User-Agent
        if hasattr(self, 'user_agent_rotation') and self.user_agent_rotation:
            self.session.headers['User-Agent'] = random.choice(self.user_agents)
        
        # Add random delay
        if self.random_delays:
            jitter = random.uniform(0, self.request_jitter)
            time.sleep(self.delay + jitter)
        
        # Call parent method
        super()._process_request(req, output)