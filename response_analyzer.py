#!/usr/bin/env python3
import hashlib
import re
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict, Counter
from dataclasses import dataclass, field
import math
import logging

@dataclass
class ResponseSignature:
    """Signature for grouping similar responses"""
    content_hash: str
    length: int
    status_code: int
    content_type: str
    title: Optional[str] = None
    count: int = 1
    paths: List[str] = field(default_factory=list)

@dataclass
class PageClassification:
    """Classification of a response"""
    is_404: bool = False
    is_soft_404: bool = False
    is_wildcard: bool = False
    is_redirect_loop: bool = False
    is_low_entropy: bool = False
    is_error_page: bool = False
    is_login_page: bool = False
    is_admin_page: bool = False
    is_api_endpoint: bool = False
    similarity_group: Optional[str] = None
    confidence: float = 0.0

class ResponseAnalyzer:
    """Intelligent response analysis and classification"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.response_signatures: Dict[str, ResponseSignature] = {}
        self.baseline_404_signature: Optional[str] = None
        self.baseline_403_signature: Optional[str] = None
        self.seen_redirects: Dict[str, int] = defaultdict(int)
        
        self.error_patterns = [
            r'404.*?not found',
            r'page.*?not.*?found',
            r'file.*?not.*?found',
            r'error 404',
            r'the requested url.*?was not found',
            r'no such file or directory',
            r'document not found'
        ]
        
        self.login_indicators = [
            r'<input[^>]*type=["\']password["\']',
            r'<form[^>]*action=["\'][^"\']*login',
            r'username.*?password',
            r'sign.*?in',
            r'log.*?in',
            r'<input[^>]*name=["\']username["\']'
        ]
        
        self.admin_indicators = [
            r'admin.*?panel',
            r'dashboard',
            r'control.*?panel',
            r'administrator',
            r'admin.*?console',
            r'management.*?interface'
        ]
        
        self.api_indicators = [
            r'application/json',
            r'application/xml',
            r'\{["\'].*?["\']:["\'].*?["\']',
            r'<\?xml',
            r'{"data":',
            r'{"error":',
            r'{"status":'
        ]
    
    def analyze_response(self, path: str, status_code: int, content: bytes, 
                        headers: dict, response_time: float) -> Tuple[Dict, PageClassification]:
        """Analyze a single response comprehensively"""
        
        classification = PageClassification()
        analysis = {
            'path': path,
            'status_code': status_code,
            'size': len(content),
            'response_time': response_time,
            'content_type': headers.get('Content-Type', ''),
            'interesting': False,
            'reasons': []
        }
        
        try:
            text_content = content.decode('utf-8', errors='ignore')
        except:
            text_content = str(content)
        
        content_hash = self._hash_content(content)
        signature = self._create_signature(content_hash, len(content), status_code, 
                                           headers.get('Content-Type', ''), text_content)
        
        if status_code == 404:
            if not self.baseline_404_signature:
                self.baseline_404_signature = signature.content_hash
                self.logger.info("Established 404 baseline signature")
            classification.is_404 = True
        
        elif status_code == 200:
            if self.baseline_404_signature and signature.content_hash == self.baseline_404_signature:
                classification.is_soft_404 = True
                classification.confidence = 0.9
                analysis['reasons'].append("Soft 404 - matches 404 signature")
            
            if self._is_error_page(text_content):
                classification.is_error_page = True
                classification.is_soft_404 = True
                analysis['reasons'].append("Error page content detected")
            
            entropy = self._calculate_entropy(content)
            if entropy < 2.5:
                classification.is_low_entropy = True
                analysis['reasons'].append(f"Low entropy content: {entropy:.2f}")
            
            if self._is_login_page(text_content):
                classification.is_login_page = True
                classification.confidence = 0.85
                analysis['interesting'] = True
                analysis['reasons'].append("Login page detected")
            
            if self._is_admin_page(text_content):
                classification.is_admin_page = True
                classification.confidence = 0.8
                analysis['interesting'] = True
                analysis['reasons'].append("Admin interface detected")
            
            if self._is_api_response(text_content, headers.get('Content-Type', '')):
                classification.is_api_endpoint = True
                analysis['interesting'] = True
                analysis['reasons'].append("API endpoint detected")
        
        elif status_code in [301, 302, 307, 308]:
            redirect_target = headers.get('Location', '')
            self.seen_redirects[path] += 1
            
            if self.seen_redirects[path] > 3:
                classification.is_redirect_loop = True
                analysis['reasons'].append("Possible redirect loop")
        
        sig_key = f"{signature.status_code}_{signature.content_hash[:16]}"
        if sig_key in self.response_signatures:
            self.response_signatures[sig_key].count += 1
            self.response_signatures[sig_key].paths.append(path)
            
            if self.response_signatures[sig_key].count > 5:
                classification.is_wildcard = True
                analysis['reasons'].append(f"Wildcard response (seen {self.response_signatures[sig_key].count} times)")
        else:
            signature.paths = [path]
            self.response_signatures[sig_key] = signature
        
        classification.similarity_group = sig_key
        
        if not classification.is_404 and not classification.is_soft_404 and \
           not classification.is_wildcard and not classification.is_low_entropy:
            analysis['interesting'] = True
        
        return analysis, classification
    
    def _hash_content(self, content: bytes) -> str:
        """Create hash of normalized content"""
        try:
            text = content.decode('utf-8', errors='ignore')
            
            text = re.sub(r'[0-9a-f]{32,}', '[HASH]', text)
            text = re.sub(r'\d{4}-\d{2}-\d{2}', '[DATE]', text)
            text = re.sub(r'\d{2}:\d{2}:\d{2}', '[TIME]', text)
            text = re.sub(r'\d+', '[NUM]', text)
            text = re.sub(r'\s+', ' ', text)
            
            return hashlib.md5(text.encode()).hexdigest()
        except:
            return hashlib.md5(content).hexdigest()
    
    def _create_signature(self, content_hash: str, length: int, status_code: int, 
                         content_type: str, text: str) -> ResponseSignature:
        """Create response signature"""
        title = None
        title_match = re.search(r'<title>(.*?)</title>', text, re.IGNORECASE | re.DOTALL)
        if title_match:
            title = title_match.group(1).strip()[:100]
        
        return ResponseSignature(
            content_hash=content_hash,
            length=length,
            status_code=status_code,
            content_type=content_type,
            title=title
        )
    
    def _calculate_entropy(self, content: bytes) -> float:
        """Calculate Shannon entropy of content"""
        if not content:
            return 0.0
        
        byte_counts = Counter(content)
        total_bytes = len(content)
        
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / total_bytes
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _is_error_page(self, content: str) -> bool:
        """Check if content looks like an error page"""
        content_lower = content.lower()
        
        for pattern in self.error_patterns:
            if re.search(pattern, content_lower):
                return True
        
        return False
    
    def _is_login_page(self, content: str) -> bool:
        """Check if content contains login form"""
        matches = 0
        
        for pattern in self.login_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                matches += 1
        
        return matches >= 2
    
    def _is_admin_page(self, content: str) -> bool:
        """Check if content is admin interface"""
        content_lower = content.lower()
        
        for pattern in self.admin_indicators:
            if re.search(pattern, content_lower):
                return True
        
        return False
    
    def _is_api_response(self, content: str, content_type: str) -> bool:
        """Check if response is an API response"""
        if 'json' in content_type.lower() or 'xml' in content_type.lower():
            return True
        
        for pattern in self.api_indicators:
            if re.search(pattern, content, re.IGNORECASE):
                return True
        
        return False
    
    def get_similar_responses(self, min_count: int = 3) -> Dict[str, List[str]]:
        """Get groups of similar responses"""
        groups = {}
        
        for sig_key, signature in self.response_signatures.items():
            if signature.count >= min_count:
                groups[sig_key] = {
                    'paths': signature.paths,
                    'count': signature.count,
                    'status': signature.status_code,
                    'size': signature.length,
                    'title': signature.title
                }
        
        return groups
    
    def get_statistics(self) -> Dict:
        """Get analysis statistics"""
        total_signatures = len(self.response_signatures)
        wildcards = sum(1 for s in self.response_signatures.values() if s.count > 5)
        
        status_distribution = defaultdict(int)
        for signature in self.response_signatures.values():
            status_distribution[signature.status_code] += signature.count
        
        return {
            'total_unique_responses': total_signatures,
            'wildcard_responses': wildcards,
            'status_distribution': dict(status_distribution),
            'redirect_loops': len([k for k, v in self.seen_redirects.items() if v > 3])
        }

class ContentExtractor:
    """Extract meaningful content from responses"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def extract_forms(self, html: str) -> List[Dict]:
        """Extract forms from HTML"""
        forms = []
        
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.finditer(form_pattern, html, re.IGNORECASE | re.DOTALL)
        
        for match in form_matches:
            form_html = match.group(0)
            
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            
            inputs = re.findall(r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>', form_html, re.IGNORECASE)
            
            forms.append({
                'action': action_match.group(1) if action_match else '',
                'method': method_match.group(1) if method_match else 'GET',
                'inputs': inputs
            })
        
        return forms
    
    def extract_links(self, html: str, base_url: str) -> Set[str]:
        """Extract internal links"""
        links = set()
        
        href_pattern = r'href=["\']([^"\']*)["\']'
        matches = re.findall(href_pattern, html, re.IGNORECASE)
        
        for match in matches:
            if match.startswith('/') and not match.startswith('//'):
                links.add(match)
            elif match.startswith(base_url):
                path = match.replace(base_url, '')
                links.add(path)
        
        return links
    
    def extract_emails(self, content: str) -> Set[str]:
        """Extract email addresses"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        emails = set(re.findall(email_pattern, content))
        return emails
    
    def extract_comments(self, html: str) -> List[str]:
        """Extract HTML comments"""
        comment_pattern = r'<!--(.*?)-->'
        comments = re.findall(comment_pattern, html, re.DOTALL)
        return [c.strip() for c in comments if c.strip()]
    
    def extract_secrets(self, content: str) -> List[Dict]:
        """Extract potential secrets or sensitive data"""
        secrets = []
        
        patterns = {
            'API Key': r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
            'Token': r'(?i)(token|auth[_-]?token)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
            'Secret': r'(?i)(secret|client[_-]?secret)\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})["\']?',
            'Password': r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{5,})["\']',
            'AWS Key': r'(?i)AKIA[0-9A-Z]{16}',
            'Private Key': r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
            'JWT': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*'
        }
        
        for secret_type, pattern in patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                secrets.append({
                    'type': secret_type,
                    'value': match.group(0)[:100],
                    'position': match.start()
                })
        
        return secrets