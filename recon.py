"""
Enhanced website reconnaissance module
"""

import requests
import ssl
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import re
import json
from typing import Dict, List, Set, Tuple
import time
import warnings
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
from requests.packages.urllib3.util import ssl_

# Suppress warnings
warnings.filterwarnings('ignore')

class SSLAdapter(HTTPAdapter):
    """Custom SSL adapter for TLS handling"""
    
    def init_poolmanager(self, connections, maxsize, block=False, **kwargs):
        ctx = ssl_.create_urllib3_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        self.poolmanager = PoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            ssl_context=ctx
        )

class WebRecon:
    """Enhanced web reconnaissance class"""
    
    def __init__(self, url, timeout=10, user_agent=None, proxy=None, cookies=None):
        self.url = self._normalize_url(url)
        self.timeout = timeout
        self.session = requests.Session()
        
        # Custom SSL context
        self.session.mount('https://', SSLAdapter())
        
        # Configure headers
        headers = {
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        self.session.headers.update(headers)
        
        # Configure proxy if provided
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
        
        # Configure cookies if provided
        if cookies:
            self._parse_cookies(cookies)
        
        # Rate limiting
        self.request_delay = 0
        self.last_request = 0
    
    def _normalize_url(self, url):
        """Normalize URL"""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def _parse_cookies(self, cookie_string):
        """Parse cookie string into session"""
        for cookie in cookie_string.split(';'):
            if '=' in cookie:
                name, value = cookie.strip().split('=', 1)
                self.session.cookies.set(name, value)
    
    def _respect_rate_limit(self):
        """Respect rate limiting if configured"""
        if self.request_delay > 0:
            elapsed = time.time() - self.last_request
            if elapsed < self.request_delay:
                time.sleep(self.request_delay - elapsed)
            self.last_request = time.time()
    
    def analyze(self, max_pages=5):
        """Perform comprehensive reconnaissance"""
        
        data = {
            'url': self.url,
            'links': [],
            'external_links': [],
            'scripts': [],
            'stylesheets': [],
            'images': [],
            'forms': [],
            'inputs': [],
            'meta_tags': [],
            'keywords': set(),
            'tech': set(),
            'headers': {},
            'cookies': {},
            'security_headers': {},
            'server_info': {},
            'content': '',
            'robots_txt': '',
            'sitemap': '',
            'subdomains': set(),
            'emails': set(),
            'phone_numbers': set(),
            'social_links': set(),
            'status_code': 0,
            'response_time': 0,
            'page_title': '',
            'page_size': 0,
            'word_count': 0,
            'language': ''
        }
        
        try:
            # Fetch homepage with timing
            start_time = time.time()
            response = self.session.get(
                self.url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False
            )
            response_time = time.time() - start_time
            
            data['status_code'] = response.status_code
            data['response_time'] = response_time
            data['page_size'] = len(response.content)
            data['headers'] = dict(response.headers)
            data['cookies'] = dict(response.cookies)
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            data['content'] = response.text
            
            # Extract page title
            if soup.title:
                data['page_title'] = soup.title.string
            
            # Extract meta tags
            for meta in soup.find_all('meta'):
                meta_data = {}
                for attr in meta.attrs:
                    meta_data[attr] = meta[attr]
                data['meta_tags'].append(meta_data)
                
                # Extract keywords from meta tags
                if meta.get('name') == 'keywords' and meta.get('content'):
                    keywords = meta['content'].split(',')
                    data['keywords'].update([k.strip().lower() for k in keywords])
                if meta.get('name') == 'description' and meta.get('content'):
                    data['keywords'].update(re.findall(r'\b\w{4,}\b', meta['content'].lower()))
            
            # Extract all links
            self._extract_links(soup, data)
            
            # Extract scripts and styles
            self._extract_resources(soup, data)
            
            # Extract forms and inputs
            self._extract_forms(soup, data)
            
            # Extract text content and analyze
            self._analyze_content(soup, data)
            
            # Detect technologies
            self._detect_technologies(response, soup, data)
            
            # Check security headers
            self._check_security_headers(response.headers, data)
            
            # Extract server information
            self._extract_server_info(response.headers, data)
            
            # Look for additional files
            self._check_additional_files(data)
            
            # Extract contact information
            self._extract_contact_info(response.text, data)
            
            # Convert sets to lists for JSON serialization
            data['keywords'] = list(data['keywords'])
            data['tech'] = list(data['tech'])
            data['subdomains'] = list(data['subdomains'])
            data['emails'] = list(data['emails'])
            data['phone_numbers'] = list(data['phone_numbers'])
            data['social_links'] = list(data['social_links'])
            
            # Clean up
            data['links'] = list(set(data['links']))
            data['scripts'] = list(set(data['scripts']))
            
        except Exception as e:
            data['error'] = str(e)
        
        return data
    
    def _extract_links(self, soup, data):
        """Extract links from page"""
        base_domain = urlparse(self.url).netloc
        
        for link in soup.find_all('a', href=True):
            href = link['href'].strip()
            
            if href.startswith('#'):
                continue
            
            # Resolve relative URLs
            if href.startswith('/'):
                full_url = urljoin(self.url, href)
                data['links'].append(href)
                
                # Extract keywords from path
                path_parts = href.strip('/').split('/')
                data['keywords'].update([p.lower() for p in path_parts if len(p) > 2])
                
                # Check for subdomains
                parsed = urlparse(full_url)
                if parsed.netloc and parsed.netloc != base_domain:
                    subdomain = parsed.netloc.replace(f'.{base_domain}', '')
                    if subdomain and subdomain != base_domain:
                        data['subdomains'].add(subdomain)
            
            elif href.startswith('http'):
                data['external_links'].append(href)
            
            # Extract link text as keywords
            if link.text:
                words = re.findall(r'\b\w{4,}\b', link.text.lower())
                data['keywords'].update(words)
    
    def _extract_resources(self, soup, data):
        """Extract scripts, stylesheets, and images"""
        # Scripts
        for script in soup.find_all('script', src=True):
            src = script['src']
            data['scripts'].append(src)
            
            # Extract keywords from script paths
            if src.startswith('/'):
                parts = src.strip('/').split('/')
                data['keywords'].update([p.lower() for p in parts if len(p) > 2])
        
        # Stylesheets
        for link in soup.find_all('link', rel='stylesheet'):
            if link.get('href'):
                data['stylesheets'].append(link['href'])
        
        # Images
        for img in soup.find_all('img', src=True):
            data['images'].append(img['src'])
    
    def _extract_forms(self, soup, data):
        """Extract forms and form inputs"""
        for form in soup.find_all('form'):
            form_data = {
                'action': form.get('action', ''),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            
            # Extract input fields
            for inp in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'type': inp.get('type', 'text'),
                    'name': inp.get('name', ''),
                    'value': inp.get('value', ''),
                    'placeholder': inp.get('placeholder', '')
                }
                form_data['inputs'].append(input_data)
            
            data['forms'].append(form_data)
    
    def _analyze_content(self, soup, data):
        """Analyze page content"""
        # Get all text
        text = soup.get_text()
        
        # Count words
        words = re.findall(r'\b\w+\b', text)
        data['word_count'] = len(words)
        
        # Extract more keywords
        content_keywords = re.findall(r'\b\w{4,}\b', text.lower())
        data['keywords'].update(content_keywords[:100])
        
        # Detect language (simple detection)
        common_english = {'the', 'and', 'for', 'you', 'are', 'this', 'that'}
        english_words = sum(1 for word in words[:100] if word.lower() in common_english)
        data['language'] = 'English' if english_words > 10 else 'Unknown'
    
    def _detect_technologies(self, response, soup, data):
        """Detect web technologies"""
        headers = response.headers
        content = response.text.lower()
        html = str(soup).lower()
        
        # Check headers
        if 'X-Powered-By' in headers:
            data['tech'].add(headers['X-Powered-By'])
        if 'Server' in headers:
            data['tech'].add(headers['Server'])
        
        # Check meta tags
        for meta in soup.find_all('meta'):
            if meta.get('name') == 'generator':
                data['tech'].add(meta.get('content', ''))
        
        # Framework detection
        tech_patterns = {
            'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
            'Django': ['csrfmiddlewaretoken', 'django'],
            'Flask': ['flask', 'session'],
            'Laravel': ['laravel', 'csrf-token'],
            'Ruby on Rails': ['rails', 'ruby'],
            'Express.js': ['express', 'node'],
            'React': ['react', 'react-dom'],
            'Vue.js': ['vue', 'vue.js'],
            'Angular': ['angular', 'ng-'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap'],
            'Tailwind': ['tailwind'],
            'PHP': ['.php', 'php/', '<?php'],
            'ASP.NET': ['.aspx', '.asp', '__viewstate'],
            'Java': ['jsp', 'servlet', 'java'],
            'Python': ['python', 'django', 'flask'],
            'Nginx': ['nginx'],
            'Apache': ['apache'],
            'IIS': ['microsoft-iis'],
            'CloudFlare': ['cloudflare'],
            'AWS': ['aws', 'amazon'],
            'Google Analytics': ['google-analytics', 'ga.js'],
            'Facebook Pixel': ['facebook', 'fbq('],
            'Stripe': ['stripe.com'],
            'PayPal': ['paypal']
        }
        
        for tech, patterns in tech_patterns.items():
            for pattern in patterns:
                if pattern in content or pattern in html:
                    data['tech'].add(tech)
                    break
        
        # CMS detection
        cms_patterns = {
            'WordPress': True,  # Already checked
            'Joomla': ['joomla', 'com_'],
            'Drupal': ['drupal', 'sites/all'],
            'Magento': ['magento', '/skin/frontend/'],
            'Shopify': ['shopify', 'shopify.shop'],
            'Wix': ['wix.com', 'wixstatic.com'],
            'Squarespace': ['squarespace', 'sqsp'],
            'Ghost': ['ghost', 'ghost.org']
        }
        
        for cms, patterns in cms_patterns.items():
            if isinstance(patterns, list):
                for pattern in patterns:
                    if pattern in content:
                        data['tech'].add(cms)
                        break
    
    def _check_security_headers(self, headers, data):
        """Check for security headers"""
        security_headers = [
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Strict-Transport-Security',
            'Referrer-Policy',
            'Permissions-Policy',
            'X-Permitted-Cross-Domain-Policies'
        ]
        
        for header in security_headers:
            if header in headers:
                data['security_headers'][header] = headers[header]
    
    def _extract_server_info(self, headers, data):
        """Extract server information"""
        data['server_info'] = {
            'server': headers.get('Server', 'Unknown'),
            'powered_by': headers.get('X-Powered-By', 'Unknown'),
            'content_type': headers.get('Content-Type', 'Unknown'),
            'cache_control': headers.get('Cache-Control', 'None'),
            'last_modified': headers.get('Last-Modified', 'None')
        }
    
    def _check_additional_files(self, data):
        """Check for robots.txt, sitemap.xml, etc."""
        additional_files = {
            'robots.txt': '/robots.txt',
            'sitemap.xml': '/sitemap.xml',
            'humans.txt': '/humans.txt',
            'security.txt': '/.well-known/security.txt',
            'ads.txt': '/ads.txt'
        }
        
        for name, path in additional_files.items():
            try:
                url = urljoin(self.url, path)
                response = self.session.get(url, timeout=self.timeout, verify=False)
                if response.status_code == 200:
                    data[name.replace('.', '_')] = response.text
            except:
                pass
    
    def _extract_contact_info(self, text, data):
        """Extract contact information"""
        # Email addresses
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, text)
        data['emails'].update(emails[:10])
        
        # Phone numbers (simple pattern)
        phone_pattern = r'[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}'
        phones = re.findall(phone_pattern, text)
        data['phone_numbers'].update(phones[:10])
        
        # Social media links
        social_patterns = {
            'facebook': r'facebook\.com/[a-zA-Z0-9._-]+',
            'twitter': r'twitter\.com/[a-zA-Z0-9._-]+',
            'linkedin': r'linkedin\.com/(in|company)/[a-zA-Z0-9._-]+',
            'instagram': r'instagram\.com/[a-zA-Z0-9._-]+',
            'youtube': r'youtube\.com/(channel|user)/[a-zA-Z0-9._-]+'
        }
        
        for platform, pattern in social_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                data['social_links'].add(f"https://{match}")
    
    def get_sitemap(self):
        """Get sitemap if available"""
        try:
            sitemap_url = urljoin(self.url, '/sitemap.xml')
            response = self.session.get(sitemap_url, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                return response.text
        except:
            pass
        return None
    
    def get_robots_txt(self):
        """Get robots.txt if available"""
        try:
            robots_url = urljoin(self.url, '/robots.txt')
            response = self.session.get(robots_url, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                return response.text
        except:
            pass
        return None

# Utility functions
def extract_domain_keywords(domain):
    """Extract keywords from domain name"""
    domain = domain.replace('www.', '').split('.')[0]
    keywords = re.findall(r'[a-zA-Z]{3,}', domain)
    return [k.lower() for k in keywords]

def analyze_response_headers(headers):
    """Analyze response headers for information"""
    info = {}
    
    if 'Server' in headers:
        info['server'] = headers['Server']
    
    if 'X-Powered-By' in headers:
        info['powered_by'] = headers['X-Powered-By']
    
    if 'Set-Cookie' in headers:
        cookies = headers.get_list('Set-Cookie')
        info['cookies'] = [c.split(';')[0] for c in cookies]
    
    return info