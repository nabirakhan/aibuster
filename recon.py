#!/usr/bin/env python3
import re
import requests
import hashlib
import json
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import logging
from dataclasses import dataclass, field

@dataclass
class TechnologyFingerprint:
    """Detailed technology fingerprint"""
    name: str
    version: Optional[str] = None
    confidence: float = 0.0
    indicators: List[str] = field(default_factory=list)
    cpe: Optional[str] = None

@dataclass
class WAFInfo:
    """WAF detection information"""
    detected: bool = False
    name: Optional[str] = None
    confidence: float = 0.0
    indicators: List[str] = field(default_factory=list)

class AdvancedWebRecon:
    """Enhanced reconnaissance with advanced detection capabilities"""
    
    def __init__(self, url: str, timeout: int = 10, user_agent: Optional[str] = None,
                 proxy: Optional[str] = None, cookies: Optional[str] = None):
        self.url = url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.logger = logging.getLogger(__name__)
        
        headers = {
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
        self.session.headers.update(headers)
        
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        
        if cookies:
            self._set_cookies(cookies)
        
        self.fingerprints: List[TechnologyFingerprint] = []
        self.waf_info: Optional[WAFInfo] = None
        self.cdn_info: Optional[str] = None
    
    def _set_cookies(self, cookies: str):
        """Set cookies from string"""
        for cookie in cookies.split(';'):
            if '=' in cookie:
                name, value = cookie.strip().split('=', 1)
                self.session.cookies.set(name, value)
    
    def analyze(self) -> Dict:
        """Perform comprehensive reconnaissance"""
        result = {
            'url': self.url,
            'tech': [],
            'server': '',
            'title': '',
            'keywords': [],
            'status_code': 0,
            'headers': {},
            'fingerprints': [],
            'waf': None,
            'cdn': None,
            'version_info': {},
            'cms': None,
            'frameworks': [],
            'database_hints': [],
            'api_endpoints': [],
            'security_headers': {}
        }
        
        try:
            self.logger.info(f"Starting advanced reconnaissance on {self.url}")
            
            response = self.session.get(self.url, timeout=self.timeout, verify=False, allow_redirects=True)
            
            result['status_code'] = response.status_code
            result['headers'] = dict(response.headers)
            result['server'] = response.headers.get('Server', 'Unknown')
            
            self._detect_waf(response)
            result['waf'] = {
                'detected': self.waf_info.detected,
                'name': self.waf_info.name,
                'confidence': self.waf_info.confidence,
                'indicators': self.waf_info.indicators
            } if self.waf_info else None
            
            self._detect_cdn(response)
            result['cdn'] = self.cdn_info
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            if soup.title:
                result['title'] = soup.title.string.strip() if soup.title.string else ''
            
            result['keywords'] = self._extract_keywords(soup, response.text)
            
            self._fingerprint_technologies(response, soup)
            
            result['tech'] = list(set([fp.name for fp in self.fingerprints]))
            result['fingerprints'] = [
                {
                    'name': fp.name,
                    'version': fp.version,
                    'confidence': fp.confidence,
                    'indicators': fp.indicators
                }
                for fp in self.fingerprints
            ]
            
            result['version_info'] = {fp.name: fp.version for fp in self.fingerprints if fp.version}
            
            result['cms'] = self._detect_cms(response, soup)
            result['frameworks'] = self._detect_frameworks(response, soup)
            result['database_hints'] = self._detect_database_hints(response, soup)
            result['api_endpoints'] = self._discover_api_endpoints(soup, response.text)
            result['security_headers'] = self._analyze_security_headers(response.headers)
            
            self.logger.info(f"Reconnaissance complete. Detected {len(result['tech'])} technologies")
            
        except requests.exceptions.Timeout:
            self.logger.error(f"Timeout connecting to {self.url}")
            result['error'] = 'Timeout'
        except requests.exceptions.ConnectionError:
            self.logger.error(f"Connection error to {self.url}")
            result['error'] = 'Connection error'
        except Exception as e:
            self.logger.error(f"Error during reconnaissance: {e}")
            result['error'] = str(e)
        
        return result
    
    def _detect_waf(self, response: requests.Response):
        """Detect Web Application Firewall"""
        waf_signatures = {
            'Cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status', '__cfduid'],
                'cookies': ['__cfduid', '__cflb'],
                'body_patterns': [r'<title>Attention Required! \| Cloudflare</title>']
            },
            'AWS WAF': {
                'headers': ['x-amzn-requestid', 'x-amz-cf-id'],
                'body_patterns': [r'AWS.*?Error', r'Request blocked']
            },
            'Akamai': {
                'headers': ['x-akamai-.*?', 'akamai-'],
                'body_patterns': [r'Reference #.*?Akamai']
            },
            'Incapsula': {
                'headers': ['x-cdn', 'x-iinfo'],
                'cookies': ['incap_ses_', 'visid_incap_'],
                'body_patterns': [r'_Incapsula_Resource']
            },
            'ModSecurity': {
                'headers': ['server'],
                'body_patterns': [r'ModSecurity', r'mod_security']
            },
            'Sucuri': {
                'headers': ['x-sucuri-id', 'x-sucuri-cache'],
                'body_patterns': [r'Sucuri WebSite Firewall']
            },
            'F5 BIG-IP': {
                'headers': ['x-wa-info'],
                'cookies': ['TS[a-z0-9]{6}', 'BIGipServer'],
                'body_patterns': []
            },
            'Imperva': {
                'cookies': ['incap_ses_'],
                'body_patterns': [r'Imperva']
            }
        }
        
        detected_wafs = []
        
        for waf_name, signatures in waf_signatures.items():
            confidence = 0.0
            indicators = []
            
            for header in signatures.get('headers', []):
                for resp_header in response.headers.keys():
                    if re.search(header, resp_header, re.IGNORECASE):
                        confidence += 0.4
                        indicators.append(f"Header: {resp_header}")
            
            for cookie_pattern in signatures.get('cookies', []):
                for cookie_name in response.cookies.keys():
                    if re.search(cookie_pattern, cookie_name, re.IGNORECASE):
                        confidence += 0.3
                        indicators.append(f"Cookie: {cookie_name}")
            
            for pattern in signatures.get('body_patterns', []):
                if re.search(pattern, response.text, re.IGNORECASE):
                    confidence += 0.5
                    indicators.append(f"Body pattern: {pattern}")
            
            if confidence > 0:
                detected_wafs.append((waf_name, confidence, indicators))
        
        if detected_wafs:
            detected_wafs.sort(key=lambda x: x[1], reverse=True)
            waf_name, confidence, indicators = detected_wafs[0]
            
            self.waf_info = WAFInfo(
                detected=True,
                name=waf_name,
                confidence=min(confidence, 1.0),
                indicators=indicators
            )
            self.logger.info(f"WAF detected: {waf_name} (confidence: {confidence:.2f})")
        else:
            self.waf_info = WAFInfo(detected=False)
    
    def _detect_cdn(self, response: requests.Response):
        """Detect CDN provider"""
        cdn_indicators = {
            'Cloudflare': ['cf-ray', 'cf-cache-status'],
            'Fastly': ['x-served-by', 'fastly'],
            'Akamai': ['x-akamai', 'akamai-'],
            'CloudFront': ['x-amz-cf-', 'cloudfront'],
            'KeyCDN': ['x-edge-', 'keycdn'],
            'StackPath': ['x-sp-', 'stackpath'],
            'BunnyCDN': ['cdn-pullzone', 'bunnycdn'],
            'Imperva': ['x-cdn'],
            'Sucuri': ['x-sucuri-cache']
        }
        
        for cdn_name, headers in cdn_indicators.items():
            for header in headers:
                for resp_header in response.headers.keys():
                    if header.lower() in resp_header.lower():
                        self.cdn_info = cdn_name
                        self.logger.info(f"CDN detected: {cdn_name}")
                        return
    
    def _fingerprint_technologies(self, response: requests.Response, soup: BeautifulSoup):
        """Comprehensive technology fingerprinting"""
        
        self._fingerprint_from_headers(response.headers)
        self._fingerprint_from_meta_tags(soup)
        self._fingerprint_from_scripts(soup)
        self._fingerprint_from_html(response.text, soup)
        self._fingerprint_from_cookies(response.cookies)
    
    def _fingerprint_from_headers(self, headers: dict):
        """Fingerprint from HTTP headers"""
        server = headers.get('Server', '')
        powered_by = headers.get('X-Powered-By', '')
        
        version_patterns = {
            'nginx': r'nginx/([\d.]+)',
            'Apache': r'Apache/([\d.]+)',
            'IIS': r'Microsoft-IIS/([\d.]+)',
            'PHP': r'PHP/([\d.]+)',
            'ASP.NET': r'ASP\.NET',
            'Express': r'Express'
        }
        
        for tech, pattern in version_patterns.items():
            combined = f"{server} {powered_by}"
            match = re.search(pattern, combined, re.IGNORECASE)
            if match:
                version = match.group(1) if match.groups() else None
                self.fingerprints.append(TechnologyFingerprint(
                    name=tech,
                    version=version,
                    confidence=0.95,
                    indicators=[f"Server header: {server or powered_by}"]
                ))
        
        if 'Jetty' in server:
            self.fingerprints.append(TechnologyFingerprint(
                name='Jetty',
                confidence=0.9,
                indicators=['Server header']
            ))
        
        if 'Tomcat' in server or 'Coyote' in server:
            self.fingerprints.append(TechnologyFingerprint(
                name='Apache Tomcat',
                confidence=0.9,
                indicators=['Server header']
            ))
    
    def _fingerprint_from_meta_tags(self, soup: BeautifulSoup):
        """Fingerprint from meta tags"""
        generators = {
            'WordPress': r'WordPress ([\d.]+)',
            'Drupal': r'Drupal ([\d.]+)',
            'Joomla': r'Joomla!? ([\d.]+)',
            'Magento': r'Magento',
            'Shopify': r'Shopify',
            'Wix': r'Wix\.com',
            'Squarespace': r'Squarespace',
            'PrestaShop': r'PrestaShop'
        }
        
        generator_tag = soup.find('meta', attrs={'name': 'generator'})
        if generator_tag and generator_tag.get('content'):
            content = generator_tag['content']
            
            for tech, pattern in generators.items():
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() else None
                    self.fingerprints.append(TechnologyFingerprint(
                        name=tech,
                        version=version,
                        confidence=0.98,
                        indicators=['Generator meta tag']
                    ))
    
    def _fingerprint_from_scripts(self, soup: BeautifulSoup):
        """Fingerprint from JavaScript libraries"""
        script_patterns = {
            'jQuery': r'jquery[.-]?([\d.]+)?(\.min)?\.js',
            'React': r'react[.-]?([\d.]+)?(\.min)?\.js',
            'Vue.js': r'vue[.-]?([\d.]+)?(\.min)?\.js',
            'Angular': r'angular[.-]?([\d.]+)?(\.min)?\.js',
            'Bootstrap': r'bootstrap[.-]?([\d.]+)?(\.min)?\.js',
            'Next.js': r'_next/static',
            'Nuxt.js': r'_nuxt',
            'Gatsby': r'gatsby',
            'D3.js': r'd3[.-]?([\d.]+)?(\.min)?\.js'
        }
        
        scripts = soup.find_all('script', src=True)
        
        for script in scripts:
            src = script.get('src', '')
            
            for tech, pattern in script_patterns.items():
                match = re.search(pattern, src, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.groups() and match.group(1) else None
                    
                    existing = next((fp for fp in self.fingerprints if fp.name == tech), None)
                    if not existing:
                        self.fingerprints.append(TechnologyFingerprint(
                            name=tech,
                            version=version,
                            confidence=0.9,
                            indicators=[f'Script: {src[:50]}']
                        ))
    
    def _fingerprint_from_html(self, html: str, soup: BeautifulSoup):
        """Fingerprint from HTML patterns"""
        
        if soup.find('meta', attrs={'name': 'shopify-checkout-api-token'}):
            self.fingerprints.append(TechnologyFingerprint(
                name='Shopify',
                confidence=1.0,
                indicators=['Shopify checkout token']
            ))
        
        if re.search(r'wp-content', html, re.IGNORECASE):
            confidence = 0.95 if soup.find('link', href=re.compile(r'wp-includes')) else 0.7
            self.fingerprints.append(TechnologyFingerprint(
                name='WordPress',
                confidence=confidence,
                indicators=['wp-content in HTML']
            ))
        
        if re.search(r'/sites/default/files', html) or re.search(r'Drupal\.settings', html):
            self.fingerprints.append(TechnologyFingerprint(
                name='Drupal',
                confidence=0.9,
                indicators=['Drupal patterns in HTML']
            ))
        
        laravel_patterns = [r'laravel_session', r'XSRF-TOKEN', r'csrf-token']
        if any(re.search(p, html, re.IGNORECASE) for p in laravel_patterns):
            self.fingerprints.append(TechnologyFingerprint(
                name='Laravel',
                confidence=0.85,
                indicators=['Laravel patterns']
            ))
        
        if re.search(r'__NEXT_DATA__', html):
            self.fingerprints.append(TechnologyFingerprint(
                name='Next.js',
                confidence=0.95,
                indicators=['__NEXT_DATA__ found']
            ))
    
    def _fingerprint_from_cookies(self, cookies):
        """Fingerprint from cookies"""
        cookie_patterns = {
            'PHP': ['PHPSESSID', 'phpMyAdmin'],
            'ASP.NET': ['ASP.NET_SessionId', 'ASPSESSIONID'],
            'Java': ['JSESSIONID'],
            'Laravel': ['laravel_session', 'XSRF-TOKEN'],
            'Django': ['sessionid', 'csrftoken'],
            'Express': ['connect.sid']
        }
        
        for tech, cookie_names in cookie_patterns.items():
            for cookie_name in cookie_names:
                if cookie_name in cookies:
                    existing = next((fp for fp in self.fingerprints if fp.name == tech), None)
                    if not existing:
                        self.fingerprints.append(TechnologyFingerprint(
                            name=tech,
                            confidence=0.85,
                            indicators=[f'Cookie: {cookie_name}']
                        ))
    
    def _detect_cms(self, response: requests.Response, soup: BeautifulSoup) -> Optional[str]:
        """Detect CMS with high confidence"""
        cms_list = [fp.name for fp in self.fingerprints if fp.name in 
                    ['WordPress', 'Drupal', 'Joomla', 'Magento', 'Shopify', 'PrestaShop']]
        
        return cms_list[0] if cms_list else None
    
    def _detect_frameworks(self, response: requests.Response, soup: BeautifulSoup) -> List[str]:
        """Detect web frameworks"""
        frameworks = [fp.name for fp in self.fingerprints if fp.name in 
                     ['Laravel', 'Django', 'Express', 'ASP.NET', 'React', 'Vue.js', 'Angular', 'Next.js']]
        
        return frameworks
    
    def _detect_database_hints(self, response: requests.Response, soup: BeautifulSoup) -> List[str]:
        """Detect database hints from errors or patterns"""
        db_hints = []
        
        error_patterns = {
            'MySQL': [r'mysql', r'SQL syntax.*?MySQL', r'mysqli'],
            'PostgreSQL': [r'PostgreSQL', r'psql', r'pg_'],
            'MSSQL': [r'Microsoft SQL Server', r'ODBC SQL Server', r'mssql'],
            'Oracle': [r'ORA-\d+', r'Oracle.*?Error'],
            'MongoDB': [r'MongoError', r'mongodb://'],
            'Redis': [r'Redis', r'REDIS']
        }
        
        html = response.text.lower()
        
        for db, patterns in error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    if db not in db_hints:
                        db_hints.append(db)
        
        return db_hints
    
    def _discover_api_endpoints(self, soup: BeautifulSoup, html: str) -> List[str]:
        """Discover API endpoints from page content"""
        endpoints = set()
        
        api_patterns = [
            r'["\']/(api|rest|graphql|v\d+)/[a-zA-Z0-9/_-]+["\']',
            r'https?://[^"\']+/(api|rest|graphql)/[^"\']+',
            r'/api/v\d+/[a-zA-Z0-9/_-]+'
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0]
                endpoints.add(match.strip('"\''))
        
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                for pattern in api_patterns:
                    matches = re.findall(pattern, script.string)
                    for match in matches:
                        if isinstance(match, tuple):
                            match = match[0]
                        endpoints.add(match.strip('"\''))
        
        return sorted(list(endpoints))[:20]
    
    def _analyze_security_headers(self, headers: dict) -> Dict:
        """Analyze security headers"""
        security_headers = {
            'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
            'Content-Security-Policy': headers.get('Content-Security-Policy'),
            'X-Frame-Options': headers.get('X-Frame-Options'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
            'X-XSS-Protection': headers.get('X-XSS-Protection'),
            'Referrer-Policy': headers.get('Referrer-Policy'),
            'Permissions-Policy': headers.get('Permissions-Policy')
        }
        
        analysis = {
            'present': [k for k, v in security_headers.items() if v],
            'missing': [k for k, v in security_headers.items() if not v],
            'headers': {k: v for k, v in security_headers.items() if v}
        }
        
        return analysis
    
    def _extract_keywords(self, soup: BeautifulSoup, html: str) -> List[str]:
        """Extract meaningful keywords from page"""
        keywords = set()
        
        meta_keywords = soup.find('meta', attrs={'name': 'keywords'})
        if meta_keywords and meta_keywords.get('content'):
            keywords.update(meta_keywords['content'].split(','))
        
        if soup.title and soup.title.string:
            words = re.findall(r'\b[a-zA-Z]{4,}\b', soup.title.string)
            keywords.update(words)
        
        headings = soup.find_all(['h1', 'h2', 'h3'])
        for heading in headings[:10]:
            if heading.string:
                words = re.findall(r'\b[a-zA-Z]{4,}\b', heading.string)
                keywords.update(words)
        
        path_keywords = re.findall(r'/([a-zA-Z]{3,})', self.url)
        keywords.update(path_keywords)
        
        common_words = {'home', 'page', 'main', 'index', 'welcome', 'about', 'contact', 
                       'privacy', 'terms', 'policy', 'site', 'website', 'company'}
        keywords = {k.strip().lower() for k in keywords if len(k.strip()) > 2}
        keywords = keywords - common_words
        
        return sorted(list(keywords))[:30]