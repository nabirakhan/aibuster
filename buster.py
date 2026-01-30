#!/usr/bin/env python3
import json
import requests
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, Empty
from urllib3.exceptions import InsecureRequestWarning
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import logging

from adaptive_threading import AdaptiveThreadPool, AdaptiveRateLimiter, SmartConnectionPool
from response_analyzer import ResponseAnalyzer, ContentExtractor

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

@dataclass
class ScanRequest:
    path: str
    method: str = "GET"
    retries: int = 0
    response_time: float = 0.0

class EnhancedPathBuster:
    """Enhanced path buster with adaptive threading and intelligent analysis"""
    
    def __init__(self, base_url: str, threads: int = 10, timeout: int = 5, 
                 delay: float = 0, retries: int = 2, proxy: Optional[str] = None, 
                 cookies: Optional[str] = None, rate_limit: Optional[int] = None,
                 user_agent: Optional[str] = None, headers: Optional[str] = None, 
                 verify_ssl: bool = False, adaptive_threads: bool = True):
        
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.delay = delay
        self.retries = retries
        self.verify_ssl = verify_ssl
        self.logger = logging.getLogger(__name__)
        
        if adaptive_threads:
            self.thread_pool = AdaptiveThreadPool(
                initial_threads=threads,
                min_threads=max(1, threads // 2),
                max_threads=min(threads * 2, 50),
                auto_adjust=True
            )
            self.logger.info("Adaptive threading enabled")
        else:
            self.thread_pool = AdaptiveThreadPool(
                initial_threads=threads,
                min_threads=threads,
                max_threads=threads,
                auto_adjust=False
            )
        
        self.rate_limiter = AdaptiveRateLimiter(
            initial_rate=rate_limit,
            auto_detect=True
        )
        
        self.connection_pool = SmartConnectionPool(max_connections=20)
        
        self.response_analyzer = ResponseAnalyzer()
        self.content_extractor = ContentExtractor()
        
        self.default_headers = {
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        
        if headers:
            if isinstance(headers, str):
                try:
                    custom_headers = json.loads(headers)
                    self.default_headers.update(custom_headers)
                except:
                    pass
        
        self.proxy = {'http': proxy, 'https': proxy} if proxy else None
        self.cookies = self._parse_cookies(cookies) if cookies else None
        
        self.request_queue = Queue()
        self.results = {
            'found': [],
            'redirects': [],
            'forbidden': [],
            'unauthorized': [],
            'errors': [],
            'interesting': [],
            'wildcards': [],
            'login_pages': [],
            'admin_pages': [],
            'api_endpoints': []
        }
        
        self.lock = threading.Lock()
        
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'soft_404s': 0,
            'wildcards': 0,
            'interesting_findings': 0
        }
    
    def _parse_cookies(self, cookie_string: str) -> Dict:
        """Parse cookie string"""
        cookies = {}
        for cookie in cookie_string.split(';'):
            if '=' in cookie:
                name, value = cookie.strip().split('=', 1)
                cookies[name] = value
        return cookies
    
    def bust(self, paths: List[str], output) -> Dict:
        """Execute path enumeration with adaptive optimization"""
        total_paths = len(paths)
        self.logger.info(f"Starting scan of {total_paths} paths")
        
        output.create_progress_bar(total_paths, "Adaptive scanning")
        
        scan_requests = [ScanRequest(path=path) for path in paths]
        for req in scan_requests:
            self.request_queue.put(req)
        
        completed_requests = 0
        
        while not self.request_queue.empty() or completed_requests < total_paths:
            current_threads = self.thread_pool.get_current_threads()
            
            active_workers = min(current_threads, self.request_queue.qsize() + 1)
            
            with ThreadPoolExecutor(max_workers=active_workers) as executor:
                futures = []
                
                for _ in range(active_workers):
                    if not self.request_queue.empty():
                        future = executor.submit(self._worker, output)
                        futures.append(future)
                
                for future in as_completed(futures):
                    try:
                        future.result()
                        completed_requests += 1
                    except Exception as e:
                        self.logger.error(f"Worker error: {e}")
            
            if completed_requests < total_paths and not self.request_queue.empty():
                time.sleep(0.1)
        
        output.complete_progress()
        
        self._post_process_results()
        
        all_stats = {
            'results': self.results,
            'statistics': self._get_comprehensive_stats(),
            'target_url': self.base_url,
            'total_paths_tested': total_paths
        }
        
        return all_stats
    
    def _worker(self, output):
        """Worker thread for processing requests"""
        try:
            req = self.request_queue.get_nowait()
        except Empty:
            return
        
        try:
            self._process_request(req, output)
        finally:
            self.request_queue.task_done()
    
    def _process_request(self, req: ScanRequest, output):
        """Process a single request with retry logic"""
        session = self.connection_pool.get_session()
        
        session.headers.update(self.default_headers)
        if self.proxy:
            session.proxies.update(self.proxy)
        if self.cookies:
            for name, value in self.cookies.items():
                session.cookies.set(name, value)
        
        for attempt in range(self.retries + 1):
            try:
                self.rate_limiter.wait()
                
                if self.delay > 0:
                    time.sleep(self.delay)
                
                start_time = time.time()
                
                response = session.get(
                    self.base_url + req.path,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=self.verify_ssl
                )
                
                response_time = time.time() - start_time
                req.response_time = response_time
                
                if self.rate_limiter.detect_rate_limit(response.status_code, response.headers):
                    self.thread_pool.record_request(response_time, False, 'rate_limit')
                    if attempt < self.retries:
                        continue
                    else:
                        break
                
                self.thread_pool.record_request(response_time, True)
                self.rate_limiter.record_success()
                
                self._process_response(req.path, response, response_time, output)
                
                break
                
            except requests.exceptions.Timeout:
                self.thread_pool.record_request(self.timeout, False, 'timeout')
                
                if attempt >= self.retries:
                    with self.lock:
                        self.stats['failed_requests'] += 1
                        self.results['errors'].append({
                            'path': req.path,
                            'error': 'Timeout'
                        })
                break
                
            except requests.exceptions.ConnectionError as e:
                self.thread_pool.record_request(0, False, 'connection')
                
                if attempt >= self.retries:
                    with self.lock:
                        self.stats['failed_requests'] += 1
                        self.results['errors'].append({
                            'path': req.path,
                            'error': f'Connection error: {str(e)}'
                        })
                break
                
            except Exception as e:
                self.thread_pool.record_request(0, False, 'unknown')
                
                if attempt >= self.retries:
                    with self.lock:
                        self.stats['failed_requests'] += 1
                        self.results['errors'].append({
                            'path': req.path,
                            'error': str(e)
                        })
                break
        
        with self.lock:
            self.stats['total_requests'] += 1
        
        output.update_progress(self.stats['total_requests'])
    
    def _process_response(self, path: str, response: requests.Response, 
                         response_time: float, output):
        """Process and analyze response"""
        
        analysis, classification = self.response_analyzer.analyze_response(
            path=path,
            status_code=response.status_code,
            content=response.content,
            headers=dict(response.headers),
            response_time=response_time
        )
        
        result = {
            'path': path,
            'status': response.status_code,
            'size': len(response.content),
            'response_time': response_time,
            'url': self.base_url + path,
            'headers': dict(response.headers),
            'content_type': response.headers.get('Content-Type', ''),
            'server': response.headers.get('Server', ''),
            'classification': {
                'is_404': classification.is_404,
                'is_soft_404': classification.is_soft_404,
                'is_wildcard': classification.is_wildcard,
                'is_login': classification.is_login_page,
                'is_admin': classification.is_admin_page,
                'is_api': classification.is_api_endpoint,
                'confidence': classification.confidence
            }
        }
        
        if 'text/html' in result['content_type']:
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')
                if soup.title and soup.title.string:
                    result['title'] = soup.title.string.strip()[:200]
                
                forms = self.content_extractor.extract_forms(response.text)
                if forms:
                    result['forms'] = forms[:5]
                
                comments = self.content_extractor.extract_comments(response.text)
                if comments:
                    result['comments'] = comments[:10]
            except:
                pass
        
        secrets = self.content_extractor.extract_secrets(response.text)
        if secrets:
            result['potential_secrets'] = secrets[:5]
            analysis['interesting'] = True
            analysis['reasons'].append(f"Found {len(secrets)} potential secrets")
        
        with self.lock:
            if classification.is_soft_404:
                self.stats['soft_404s'] += 1
            
            if classification.is_wildcard:
                self.stats['wildcards'] += 1
                self.results['wildcards'].append(result)
            
            elif response.status_code == 200 and not classification.is_soft_404:
                self.results['found'].append(result)
                self.stats['successful_requests'] += 1
                
                if classification.is_login_page:
                    self.results['login_pages'].append(result)
                    self.stats['interesting_findings'] += 1
                    output.found(path, response.status_code, len(response.content), 
                               response_time, result['content_type'], "[LOGIN]")
                
                elif classification.is_admin_page:
                    self.results['admin_pages'].append(result)
                    self.stats['interesting_findings'] += 1
                    output.found(path, response.status_code, len(response.content), 
                               response_time, result['content_type'], "[ADMIN]")
                
                elif classification.is_api_endpoint:
                    self.results['api_endpoints'].append(result)
                    self.stats['interesting_findings'] += 1
                    output.found(path, response.status_code, len(response.content), 
                               response_time, result['content_type'], "[API]")
                
                elif analysis.get('interesting'):
                    self.results['interesting'].append(result)
                    self.stats['interesting_findings'] += 1
                    reasons = ' | '.join(analysis.get('reasons', [])[:2])
                    output.found(path, response.status_code, len(response.content), 
                               response_time, result['content_type'], f"[!] {reasons}")
                else:
                    output.found(path, response.status_code, len(response.content), 
                               response_time, result['content_type'])
            
            elif response.status_code in [301, 302, 307, 308]:
                result['redirect_location'] = response.headers.get('Location', '')
                self.results['redirects'].append(result)
                output.found(path, response.status_code, len(response.content), 
                           response_time, result['content_type'])
            
            elif response.status_code == 403:
                self.results['forbidden'].append(result)
                output.found(path, response.status_code, len(response.content), 
                           response_time, result['content_type'])
            
            elif response.status_code == 401:
                self.results['unauthorized'].append(result)
                output.found(path, response.status_code, len(response.content), 
                           response_time, result['content_type'])
    
    def _post_process_results(self):
        """Post-process results for additional insights"""
        similar_groups = self.response_analyzer.get_similar_responses(min_count=3)
        
        if similar_groups:
            self.logger.info(f"Found {len(similar_groups)} groups of similar responses")
            self.results['similar_response_groups'] = similar_groups
    
    def _get_comprehensive_stats(self) -> Dict:
        """Get comprehensive statistics"""
        base_stats = {
            'total_requests': self.stats['total_requests'],
            'successful_requests': self.stats['successful_requests'],
            'failed_requests': self.stats['failed_requests'],
            'soft_404s': self.stats['soft_404s'],
            'wildcards': self.stats['wildcards'],
            'interesting_findings': self.stats['interesting_findings'],
            'login_pages_found': len(self.results['login_pages']),
            'admin_pages_found': len(self.results['admin_pages']),
            'api_endpoints_found': len(self.results['api_endpoints'])
        }
        
        thread_stats = self.thread_pool.get_statistics()
        rate_stats = self.rate_limiter.get_statistics()
        pool_stats = self.connection_pool.get_statistics()
        analyzer_stats = self.response_analyzer.get_statistics()
        
        return {
            **base_stats,
            'threading': thread_stats,
            'rate_limiting': rate_stats,
            'connection_pool': pool_stats,
            'response_analysis': analyzer_stats
        }
    
    def cleanup(self):
        """Cleanup resources"""
        self.connection_pool.cleanup()