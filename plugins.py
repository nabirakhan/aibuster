import importlib
import inspect
from typing import Dict, List, Any
from abc import ABC, abstractmethod
import re
import json
import requests

class Plugin(ABC):
    @abstractmethod
    def get_name(self) -> str:
        pass
    @abstractmethod
    def get_description(self) -> str:
        pass
    @abstractmethod
    def run(self, recon_data: Dict, scan_results: Dict) -> Dict:
        pass
    @abstractmethod
    def get_results(self) -> Dict:
        pass

class WordPressScanner(Plugin):
    def __init__(self):
        self.name = "WordPress Security Scanner"
        self.results = {'is_wordpress': False, 'version': None, 'plugins': [], 'themes': [], 'users': [], 
                       'vulnerabilities': [], 'security_issues': [], 'exposed_files': []}
    def get_name(self):
        return self.name
    def get_description(self):
        return "Comprehensive WordPress security scanner - detects version, plugins, themes, users, and vulnerabilities"
    def run(self, recon_data, scan_results):
        print(f"[*] Running {self.name}...")
        if not self._is_wordpress(recon_data):
            print("[-] Not a WordPress site")
            return {'error': 'Not a WordPress site'}
        self.results['is_wordpress'] = True
        print("[+] WordPress detected!")
        self._detect_version(recon_data, scan_results)
        self._scan_plugins(scan_results)
        self._scan_themes(scan_results)
        self._enumerate_users(recon_data, scan_results)
        self._check_vulnerabilities(scan_results)
        self._check_security_issues(scan_results)
        return self.results
    def get_results(self):
        return self.results
    def _is_wordpress(self, recon_data):
        tech = recon_data.get('tech', [])
        content = recon_data.get('content', '')
        links = str(recon_data.get('links', []))
        wordpress_indicators = ['WordPress' in tech, 'wp-content' in content, 'wp-includes' in content, 
                               '/wp-admin' in links, '/wp-json' in links, 'wp-content' in links, '/xmlrpc.php' in links]
        return any(wordpress_indicators)
    def _detect_version(self, recon_data, scan_results):
        print("[*] Detecting WordPress version...")
        for result in scan_results.get('found', []):
            path = result.get('path', '').lower()
            if 'readme.html' in path:
                self.results['exposed_files'].append('/readme.html')
                self.results['version'] = 'Detected (check /readme.html)'
                print(f"[+] Version info exposed in readme.html")
            if 'license.txt' in path:
                self.results['exposed_files'].append('/license.txt')
    def _scan_plugins(self, scan_results):
        print("[*] Scanning for WordPress plugins...")
        plugins = set()
        for result in scan_results.get('found', []):
            path = result.get('path', '')
            if '/wp-content/plugins/' in path:
                parts = path.split('/wp-content/plugins/')
                if len(parts) > 1:
                    plugin_name = parts[1].split('/')[0]
                    if plugin_name:
                        plugins.add(plugin_name)
        self.results['plugins'] = list(plugins)
        if plugins:
            print(f"[+] Found {len(plugins)} WordPress plugins:")
            for plugin in list(plugins)[:10]:
                print(f"    - {plugin}")
    def _scan_themes(self, scan_results):
        print("[*] Scanning for WordPress themes...")
        themes = set()
        for result in scan_results.get('found', []):
            path = result.get('path', '')
            if '/wp-content/themes/' in path:
                parts = path.split('/wp-content/themes/')
                if len(parts) > 1:
                    theme_name = parts[1].split('/')[0]
                    if theme_name and theme_name not in ['twentytwenty', 'twentytwentyone']:
                        themes.add(theme_name)
        self.results['themes'] = list(themes)
        if themes:
            print(f"[+] Found {len(themes)} WordPress themes:")
            for theme in list(themes)[:10]:
                print(f"    - {theme}")
    def _enumerate_users(self, recon_data, scan_results):
        print("[*] Checking for user enumeration...")
        for result in scan_results.get('found', []):
            path = result.get('path', '')
            if '/wp-json/wp/v2/users' in path:
                self.results['users'].append('REST API user enumeration possible')
                self.results['security_issues'].append({
                    'issue': 'User Enumeration via REST API', 'severity': 'Medium', 'path': path,
                    'description': 'WordPress REST API exposes user information'
                })
                print("[!] User enumeration possible via REST API")
    def _check_vulnerabilities(self, scan_results):
        print("[*] Checking for vulnerabilities...")
        vulnerabilities = []
        for result in scan_results.get('found', []):
            path = result.get('path', '')
            status = result.get('status', 0)
            if 'xmlrpc.php' in path and status == 200:
                vulnerabilities.append({'type': 'XMLRPC Enabled', 'severity': 'Medium', 'path': path,
                                      'description': 'XMLRPC can be used for brute force attacks'})
            if 'debug.log' in path and status == 200:
                vulnerabilities.append({'type': 'Debug Log Exposed', 'severity': 'High', 'path': path,
                                      'description': 'Debug log may contain sensitive information'})
            if 'wp-config' in path and status == 200:
                vulnerabilities.append({'type': 'Config Backup Exposed', 'severity': 'Critical', 'path': path,
                                      'description': 'WordPress configuration backup file is accessible'})
        self.results['vulnerabilities'] = vulnerabilities
        if vulnerabilities:
            print(f"[!] Found {len(vulnerabilities)} vulnerabilities:")
            for vuln in vulnerabilities:
                print(f"    [{vuln['severity']}] {vuln['type']}: {vuln['path']}")
    def _check_security_issues(self, scan_results):
        print("[*] Checking for security misconfigurations...")
        issues = []
        for result in scan_results.get('found', []):
            path = result.get('path', '')
            if any(p in path for p in ['/wp-admin', '/wp-login.php']):
                if result.get('status') == 200:
                    issues.append({'issue': 'Admin Area Accessible', 'severity': 'Low', 'path': path,
                                 'description': 'WordPress admin login page is accessible'})
        self.results['security_issues'].extend(issues)

class SensitiveFileScanner(Plugin):
    def __init__(self):
        self.name = "Sensitive Files Scanner"
        self.results = {'sensitive_files': [], 'critical_findings': [], 'high_findings': [], 
                       'medium_findings': [], 'low_findings': []}
    def get_name(self):
        return self.name
    def get_description(self):
        return "Detects exposed sensitive files and configurations with severity ratings"
    def run(self, recon_data, scan_results):
        print(f"[*] Running {self.name}...")
        self._scan_for_sensitive_files(scan_results)
        return self.results
    def get_results(self):
        return self.results
    def _scan_for_sensitive_files(self, scan_results):
        print("[*] Scanning for sensitive files...")
        sensitive_patterns = {
            'Critical': ['.env', 'password', 'secret', 'credential', 'private', '.pem', '.key', 'id_rsa'],
            'High': ['config', 'database', '.git', '.svn', 'backup.sql', 'dump.sql', 'admin'],
            'Medium': ['.log', 'error_log', 'debug', '.bak', '.backup', '.old', '.zip', '.tar'],
            'Low': ['readme', 'license', 'info.php', 'phpinfo']
        }
        for result in scan_results.get('found', []):
            path = result.get('path', '').lower()
            for severity, patterns in sensitive_patterns.items():
                for pattern in patterns:
                    if pattern in path:
                        finding = {'path': result.get('path'), 'severity': severity, 'status': result.get('status'),
                                 'size': result.get('size'), 'pattern': pattern}
                        self.results['sensitive_files'].append(finding)
                        if severity == 'Critical':
                            self.results['critical_findings'].append(finding)
                        elif severity == 'High':
                            self.results['high_findings'].append(finding)
                        elif severity == 'Medium':
                            self.results['medium_findings'].append(finding)
                        else:
                            self.results['low_findings'].append(finding)
                        break
        critical_count = len(self.results['critical_findings'])
        high_count = len(self.results['high_findings'])
        medium_count = len(self.results['medium_findings'])
        low_count = len(self.results['low_findings'])
        total = critical_count + high_count + medium_count + low_count
        if total > 0:
            print(f"[+] Found {total} sensitive files:")
            if critical_count > 0:
                print(f"    [CRITICAL] {critical_count} critical findings")
            if high_count > 0:
                print(f"    [HIGH] {high_count} high-severity findings")
            if medium_count > 0:
                print(f"    [MEDIUM] {medium_count} medium-severity findings")
            if low_count > 0:
                print(f"    [LOW] {low_count} low-severity findings")
        else:
            print("[-] No sensitive files detected")

class APIScanner(Plugin):
    def __init__(self):
        self.name = "API Security Scanner"
        self.results = {'endpoints': [], 'api_types': [], 'security_issues': [], 'documentation': []}
    def get_name(self):
        return self.name
    def get_description(self):
        return "Discovers and analyzes API endpoints (REST, GraphQL, SOAP)"
    def run(self, recon_data, scan_results):
        print(f"[*] Running {self.name}...")
        api_endpoints = self._find_api_endpoints(scan_results)
        if not api_endpoints:
            print("[-] No API endpoints found")
            return self.results
        print(f"[+] Found {len(api_endpoints)} API endpoints")
        for endpoint in api_endpoints:
            endpoint_info = self._analyze_endpoint(endpoint, scan_results)
            if endpoint_info:
                self.results['endpoints'].append(endpoint_info)
        self._check_security_issues()
        self._check_documentation(scan_results)
        return self.results
    def get_results(self):
        return self.results
    def _find_api_endpoints(self, scan_results):
        endpoints = []
        api_patterns = [r'/api/', r'/v\d+/', r'/graphql', r'/graphiql', r'/rest/', r'/json/', r'/xml/', r'/soap',
                       r'/webhook', r'/webapi', r'/services/', r'/ws/', r'/rpc']
        for result in scan_results.get('found', []):
            path = result.get('path', '')
            content_type = result.get('content_type', '')
            for pattern in api_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    endpoints.append({'path': path, 'status': result.get('status'), 'size': result.get('size'),
                                    'content_type': content_type})
                    break
            if 'json' in content_type.lower() or 'xml' in content_type.lower():
                if path not in [e['path'] for e in endpoints]:
                    endpoints.append({'path': path, 'status': result.get('status'), 'size': result.get('size'),
                                    'content_type': content_type})
        return endpoints
    def _analyze_endpoint(self, endpoint, scan_results):
        path = endpoint['path']
        api_type = 'REST'
        if 'graphql' in path.lower():
            api_type = 'GraphQL'
        elif 'soap' in path.lower():
            api_type = 'SOAP'
        endpoint_info = {'path': path, 'type': api_type, 'status': endpoint['status'], 'content_type': endpoint['content_type'],
                        'methods': ['GET'], 'authentication': 'Unknown', 'issues': []}
        if endpoint['status'] == 401:
            endpoint_info['authentication'] = 'Required'
            endpoint_info['issues'].append('Authentication required')
        elif endpoint['status'] == 403:
            endpoint_info['authentication'] = 'Forbidden'
            endpoint_info['issues'].append('Access forbidden')
        elif endpoint['status'] == 200:
            endpoint_info['authentication'] = 'None or weak'
            endpoint_info['issues'].append('No authentication required')
        return endpoint_info
    def _check_security_issues(self):
        issues = []
        for endpoint in self.results['endpoints']:
            path = endpoint['path']
            if any(param in path.lower() for param in ['api_key', 'token', 'secret', 'password']):
                issues.append({'severity': 'High', 'issue': 'Sensitive parameter in URL', 'path': path,
                             'description': 'API credentials should not be passed in URL'})
            if re.search(r'/v\d+/', path):
                issues.append({'severity': 'Low', 'issue': 'API version disclosed', 'path': path,
                             'description': 'API version number exposed in path'})
            if endpoint['authentication'] == 'None or weak':
                issues.append({'severity': 'High', 'issue': 'No authentication required', 'path': path,
                             'description': 'API endpoint accessible without authentication'})
        self.results['security_issues'] = issues
        if issues:
            print(f"[!] Found {len(issues)} API security issues")
    def _check_documentation(self, scan_results):
        doc_patterns = ['/api/docs', '/api/documentation', '/swagger', '/api-docs', '/graphiql', '/graphql-playground']
        for result in scan_results.get('found', []):
            path = result.get('path', '')
            for pattern in doc_patterns:
                if pattern in path.lower():
                    self.results['documentation'].append({'path': path, 'status': result.get('status')})
                    print(f"[+] API documentation found: {path}")

class ShopifyScanner(Plugin):
    def __init__(self):
        self.name = "Shopify Security Scanner"
        self.results = {'is_shopify': False, 'store_info': {}, 'products': [], 'collections': [], 'exposed_endpoints': [],
                       'security_issues': [], 'configuration': {}}
    def get_name(self):
        return self.name
    def get_description(self):
        return "Comprehensive Shopify store scanner - detects configurations, exposed data, and security issues"
    def run(self, recon_data, scan_results):
        print(f"[*] Running {self.name}...")
        if not self._is_shopify(recon_data):
            print("[-] Not a Shopify store")
            return {'error': 'Not a Shopify store'}
        self.results['is_shopify'] = True
        print("[+] Shopify store detected!")
        self._scan_store_info(recon_data, scan_results)
        self._scan_products(scan_results)
        self._scan_collections(scan_results)
        self._check_exposed_endpoints(scan_results)
        self._check_security_issues(scan_results)
        return self.results
    def get_results(self):
        return self.results
    def _is_shopify(self, recon_data):
        tech = recon_data.get('tech', [])
        content = recon_data.get('content', '')
        links = str(recon_data.get('links', []))
        headers = recon_data.get('headers', {})
        shopify_indicators = ['Shopify' in tech, 'shopify' in content.lower(), 'myshopify.com' in links.lower(),
                            'cdn.shopify.com' in content.lower(), 'X-Shopify-Stage' in headers, 'shopify' in str(headers).lower()]
        return any(shopify_indicators)
    def _scan_store_info(self, recon_data, scan_results):
        print("[*] Gathering store information...")
        self.results['store_info']['url'] = recon_data.get('url', '')
        for result in scan_results.get('found', []):
            path = result.get('path', '').lower()
            if '/shop.json' in path or '/meta.json' in path:
                self.results['exposed_endpoints'].append(path)
                self.results['store_info']['metadata_exposed'] = True
                print(f"[+] Store metadata endpoint found: {path}")
    def _scan_products(self, scan_results):
        print("[*] Scanning for product endpoints...")
        products = set()
        for result in scan_results.get('found', []):
            path = result.get('path', '')
            if '/products' in path and '.json' in path:
                products.add(path)
                self.results['exposed_endpoints'].append(path)
            if '/products.json' in path:
                self.results['configuration']['products_json_accessible'] = True
                print(f"[+] Products JSON endpoint accessible: {path}")
        self.results['products'] = list(products)
        if products:
            print(f"[+] Found {len(products)} product-related endpoints")
    def _scan_collections(self, scan_results):
        print("[*] Scanning for collection endpoints...")
        collections = set()
        for result in scan_results.get('found', []):
            path = result.get('path', '')
            if '/collections' in path and '.json' in path:
                collections.add(path)
                self.results['exposed_endpoints'].append(path)
            if '/collections.json' in path:
                self.results['configuration']['collections_json_accessible'] = True
                print(f"[+] Collections JSON endpoint accessible: {path}")
        self.results['collections'] = list(collections)
        if collections:
            print(f"[+] Found {len(collections)} collection-related endpoints")
    def _check_exposed_endpoints(self, scan_results):
        print("[*] Checking for exposed Shopify endpoints...")
        sensitive_endpoints = ['/admin', '/cart.json', '/checkout', '/checkout.json', '/orders.json', '/account',
                             '/api/graphql', '/api/2021-01/graphql.json', '/pages.json', '/blogs.json']
        for result in scan_results.get('found', []):
            path = result.get('path', '')
            for endpoint in sensitive_endpoints:
                if endpoint in path.lower():
                    self.results['exposed_endpoints'].append(path)
                    if result.get('status') == 200:
                        print(f"[!] Exposed endpoint accessible: {path}")
    def _check_security_issues(self, scan_results):
        print("[*] Checking for security issues...")
        issues = []
        for result in scan_results.get('found', []):
            path = result.get('path', '')
            status = result.get('status', 0)
            if '/cart.json' in path and status == 200:
                issues.append({'issue': 'Cart API Accessible', 'severity': 'Medium', 'path': path,
                             'description': 'Cart JSON endpoint is publicly accessible'})
            if '/products.json' in path and status == 200:
                issues.append({'issue': 'Product Data Exposed', 'severity': 'Low', 'path': path,
                             'description': 'Product catalog is publicly accessible via JSON'})
            if '/admin' in path and status == 200:
                issues.append({'issue': 'Admin Area Accessible', 'severity': 'High', 'path': path,
                             'description': 'Shopify admin area may be accessible'})
            if '/api' in path and status == 200:
                issues.append({'issue': 'API Endpoint Accessible', 'severity': 'Medium', 'path': path,
                             'description': 'Shopify API endpoint is accessible'})
            if '/graphql' in path and status == 200:
                issues.append({'issue': 'GraphQL Endpoint Accessible', 'severity': 'Medium', 'path': path,
                             'description': 'Shopify GraphQL API is accessible'})
        self.results['security_issues'] = issues
        if issues:
            print(f"[!] Found {len(issues)} security issues:")
            for issue in issues:
                print(f"    [{issue['severity']}] {issue['issue']}: {issue['path']}")
        else:
            print("[+] No major security issues detected")

class PluginManager:
    def __init__(self, plugin_names, args):
        self.plugin_names = plugin_names
        self.args = args
        self.plugins = []
        self.results = {}
    def load_plugins(self):
        available_plugins = {'wordpress': WordPressScanner, 'api-scanner': APIScanner, 
                           'sensitive-files': SensitiveFileScanner, 'shopify': ShopifyScanner}
        print(f"[*] Loading plugins...")
        for name in self.plugin_names:
            if name in available_plugins:
                plugin_class = available_plugins[name]
                plugin_instance = plugin_class()
                self.plugins.append(plugin_instance)
                print(f"[+] Loaded plugin: {plugin_instance.get_name()}")
            else:
                print(f"[!] Plugin '{name}' not found")
                print(f"[i] Available plugins: {', '.join(available_plugins.keys())}")
    def run_plugins(self, recon_data, scan_results):
        results = {}
        print(f"\n[*] Running {len(self.plugins)} plugin(s)...\n")
        for plugin in self.plugins:
            try:
                print(f"[*] {plugin.get_name()}")
                plugin_result = plugin.run(recon_data, scan_results)
                results[plugin.get_name()] = plugin_result
                print(f"[+] {plugin.get_name()} completed\n")
            except Exception as e:
                print(f"[-] Error running plugin {plugin.get_name()}: {str(e)}\n")
                results[plugin.get_name()] = {'error': str(e)}
        self.results = results
        return results
    def save_plugin_results(self, output_file):
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
    def get_available_plugins(self):
        return [('wordpress', 'WordPress security and vulnerability scanner'),
                ('api-scanner', 'API endpoint discovery and security analysis'),
                ('sensitive-files', 'Sensitive file and configuration detector'),
                ('shopify', 'Shopify store security scanner and data analyzer')]