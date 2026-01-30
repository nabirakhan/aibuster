"""
Enhanced Plugin System for AIBuster
Includes: WordPress Scanner, Sensitive Files Scanner, API Scanner
"""

import importlib
import inspect
from typing import Dict, List, Any
from abc import ABC, abstractmethod
import re
import json
import requests

class Plugin(ABC):
    """Base plugin class"""
    
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
    """Enhanced WordPress vulnerability scanner"""
    
    def __init__(self):
        self.name = "WordPress Security Scanner"
        self.results = {
            'is_wordpress': False,
            'version': None,
            'plugins': [],
            'themes': [],
            'users': [],
            'vulnerabilities': [],
            'security_issues': [],
            'exposed_files': []
        }
    
    def get_name(self):
        return self.name
    
    def get_description(self):
        return "Comprehensive WordPress security scanner - detects version, plugins, themes, users, and vulnerabilities"
    
    def run(self, recon_data, scan_results):
        """Run comprehensive WordPress scan"""
        
        print(f"[*] Running {self.name}...")
        
        # Check if site is WordPress
        if not self._is_wordpress(recon_data):
            print("[-] Not a WordPress site")
            return {'error': 'Not a WordPress site'}
        
        self.results['is_wordpress'] = True
        print("[+] WordPress detected!")
        
        # Gather WordPress information
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
        """Check if site is WordPress"""
        tech = recon_data.get('tech', [])
        content = recon_data.get('content', '')
        links = str(recon_data.get('links', []))
        
        wordpress_indicators = [
            'WordPress' in tech,
            'wp-content' in content,
            'wp-includes' in content,
            '/wp-admin' in links,
            '/wp-json' in links,
            'wp-content' in links,
            '/xmlrpc.php' in links
        ]
        
        return any(wordpress_indicators)
    
    def _detect_version(self, recon_data, scan_results):
        """Detect WordPress version"""
        print("[*] Detecting WordPress version...")
        
        # Check multiple sources
        version_sources = [
            ('readme.html', r'Version\s+(\d+\.\d+\.?\d*)'),
            ('license.txt', r'WordPress\s+(\d+\.\d+\.?\d*)'),
            ('rss', r'generator.*WordPress\s+(\d+\.\d+\.?\d*)'),
        ]
        
        for result in scan_results.get('found', []):
            path = result.get('path', '').lower()
            
            # Check readme.html
            if 'readme.html' in path:
                self.results['exposed_files'].append('/readme.html')
                self.results['version'] = 'Detected (check /readme.html)'
                print(f"[+] Version info exposed in readme.html")
            
            # Check license.txt
            if 'license.txt' in path:
                self.results['exposed_files'].append('/license.txt')
    
    def _scan_plugins(self, scan_results):
        """Scan for installed WordPress plugins"""
        print("[*] Scanning for WordPress plugins...")
        
        plugins = set()
        
        for result in scan_results.get('found', []):
            path = result.get('path', '')
            
            # Extract plugin names from wp-content/plugins/
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
        """Scan for installed WordPress themes"""
        print("[*] Scanning for WordPress themes...")
        
        themes = set()
        
        for result in scan_results.get('found', []):
            path = result.get('path', '')
            
            # Extract theme names from wp-content/themes/
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
        """Enumerate WordPress users"""
        print("[*] Checking for user enumeration...")
        
        # Check for common users
        common_users = ['admin', 'administrator', 'user', 'test']
        
        for result in scan_results.get('found', []):
            path = result.get('path', '')
            
            # Check WordPress REST API user endpoint
            if '/wp-json/wp/v2/users' in path:
                self.results['users'].append('REST API user enumeration possible')
                self.results['security_issues'].append({
                    'issue': 'User Enumeration via REST API',
                    'severity': 'Medium',
                    'path': path,
                    'description': 'WordPress REST API exposes user information'
                })
                print("[!] User enumeration possible via REST API")
    
    def _check_vulnerabilities(self, scan_results):
        """Check for common WordPress vulnerabilities"""
        print("[*] Checking for vulnerabilities...")
        
        vulnerabilities = []
        
        for result in scan_results.get('found', []):
            path = result.get('path', '')
            status = result.get('status', 0)
            
            # Check XMLRPC
            if 'xmlrpc.php' in path and status == 200:
                vulnerabilities.append({
                    'type': 'XMLRPC Enabled',
                    'severity': 'Medium',
                    'path': path,
                    'description': 'XMLRPC can be used for brute force attacks'
                })
            
            # Check debug.log
            if 'debug.log' in path and status == 200:
                vulnerabilities.append({
                    'type': 'Debug Log Exposed',
                    'severity': 'High',
                    'path': path,
                    'description': 'Debug log may contain sensitive information'
                })
            
            # Check wp-config backup
            if 'wp-config' in path and 'backup' in path.lower():
                vulnerabilities.append({
                    'type': 'Config Backup Exposed',
                    'severity': 'Critical',
                    'path': path,
                    'description': 'WordPress config backup contains database credentials'
                })
        
        self.results['vulnerabilities'] = vulnerabilities
        
        if vulnerabilities:
            print(f"[!] Found {len(vulnerabilities)} potential vulnerabilities")
    
    def _check_security_issues(self, scan_results):
        """Check for WordPress security misconfigurations"""
        print("[*] Checking for security issues...")
        
        issues = []
        
        for result in scan_results.get('found', []):
            path = result.get('path', '')
            status = result.get('status', 0)
            
            # Directory listing
            if path.endswith('/wp-content/uploads/') and status == 200:
                issues.append({
                    'issue': 'Directory Listing Enabled',
                    'severity': 'Low',
                    'path': path
                })
            
            # Exposed license/readme
            if any(file in path for file in ['readme.html', 'license.txt']) and status == 200:
                issues.append({
                    'issue': 'Version Disclosure',
                    'severity': 'Low',
                    'path': path
                })
        
        self.results['security_issues'].extend(issues)

class SensitiveFileScanner(Plugin):
    """Enhanced sensitive file scanner"""
    
    def __init__(self):
        self.name = "Sensitive File Scanner"
        self.results = {
            'sensitive_files': [],
            'backup_files': [],
            'config_files': [],
            'log_files': [],
            'vcs_files': [],
            'critical_exposures': []
        }
    
    def get_name(self):
        return self.name
    
    def get_description(self):
        return "Scans for sensitive files like configs, backups, logs, and version control artifacts"
    
    def run(self, recon_data, scan_results):
        """Scan for sensitive files"""
        
        print(f"[*] Running {self.name}...")
        
        sensitive_patterns = {
            'sensitive_files': [
                r'\.env$', r'\.env\.(local|prod|dev)',
                r'config\.(php|json|yml|yaml|xml|ini)$',
                r'\.htaccess$', r'\.htpasswd$',
                r'web\.config$', r'\.DS_Store$',
                r'password', r'secret', r'key\.', r'credentials'
            ],
            'backup_files': [
                r'\.bak$', r'\.old$', r'\.backup$', r'\.swp$',
                r'backup', r'dump\.', r'\.sql$',
                r'\.tar\.gz$', r'\.zip$', r'\.rar$',
                r'~$', r'\.save$'
            ],
            'config_files': [
                r'config/', r'conf/', r'settings/',
                r'configuration/', r'\.config/',
                r'database\.', r'db\.', r'\.ini$'
            ],
            'log_files': [
                r'\.log$', r'logs?/', r'error_log',
                r'access_log', r'debug\.log$',
                r'application\.log', r'laravel\.log'
            ],
            'vcs_files': [
                r'\.git/', r'\.svn/', r'\.hg/',
                r'\.gitignore$', r'\.gitconfig$'
            ]
        }
        
        for result in scan_results.get('found', []):
            path = result.get('path', '')
            status = result.get('status', 0)
            size = result.get('size', 0)
            
            file_info = {
                'path': path,
                'status': status,
                'size': size,
                'severity': 'Unknown'
            }
            
            # Categorize and assess severity
            for category, patterns in sensitive_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, path, re.IGNORECASE):
                        
                        # Assess severity
                        if any(x in path.lower() for x in ['.env', 'password', 'secret', 'key', 'credential']):
                            file_info['severity'] = 'Critical'
                            self.results['critical_exposures'].append(file_info.copy())
                        elif any(x in path.lower() for x in ['config', 'database', '.git']):
                            file_info['severity'] = 'High'
                        elif any(x in path.lower() for x in ['backup', '.sql', 'dump']):
                            file_info['severity'] = 'High'
                        elif any(x in path.lower() for x in ['log', '.bak']):
                            file_info['severity'] = 'Medium'
                        else:
                            file_info['severity'] = 'Low'
                        
                        self.results[category].append(file_info.copy())
                        break
        
        # Remove duplicates
        for category in self.results:
            if isinstance(self.results[category], list):
                seen = set()
                unique = []
                for item in self.results[category]:
                    path = item.get('path', '')
                    if path not in seen:
                        seen.add(path)
                        unique.append(item)
                self.results[category] = unique
        
        # Print summary
        total = sum(len(v) for v in self.results.values() if isinstance(v, list))
        if total > 0:
            print(f"[+] Found {total} sensitive files:")
            if self.results['critical_exposures']:
                print(f"    [!] Critical: {len(self.results['critical_exposures'])}")
            if self.results['config_files']:
                print(f"    [!] Config files: {len(self.results['config_files'])}")
            if self.results['backup_files']:
                print(f"    [!] Backup files: {len(self.results['backup_files'])}")
            if self.results['vcs_files']:
                print(f"    [!] VCS artifacts: {len(self.results['vcs_files'])}")
        
        return self.results
    
    def get_results(self):
        return self.results

class APIScanner(Plugin):
    """Enhanced API endpoint scanner and analyzer"""
    
    def __init__(self):
        self.name = "API Security Scanner"
        self.results = {
            'endpoints': [],
            'methods': {},
            'parameters': [],
            'security_issues': [],
            'authentication': [],
            'documentation': []
        }
    
    def get_name(self):
        return self.name
    
    def get_description(self):
        return "Discovers and analyzes API endpoints for security issues"
    
    def run(self, recon_data, scan_results):
        """Run API security scan"""
        
        print(f"[*] Running {self.name}...")
        
        # Find API endpoints
        api_endpoints = self._find_api_endpoints(scan_results)
        
        if not api_endpoints:
            print("[-] No API endpoints found")
            return self.results
        
        print(f"[+] Found {len(api_endpoints)} API endpoints")
        
        # Analyze endpoints
        for endpoint in api_endpoints:
            endpoint_info = self._analyze_endpoint(endpoint, scan_results)
            if endpoint_info:
                self.results['endpoints'].append(endpoint_info)
        
        # Check for common security issues
        self._check_security_issues()
        
        # Check for API documentation
        self._check_documentation(scan_results)
        
        return self.results
    
    def get_results(self):
        return self.results
    
    def _find_api_endpoints(self, scan_results):
        """Find potential API endpoints"""
        endpoints = []
        
        api_patterns = [
            r'/api/',
            r'/v\d+/',
            r'/graphql',
            r'/graphiql',
            r'/rest/',
            r'/json/',
            r'/xml/',
            r'/soap',
            r'/webhook',
            r'/webapi',
            r'/services/',
            r'/ws/',
            r'/rpc'
        ]
        
        for result in scan_results.get('found', []):
            path = result.get('path', '')
            content_type = result.get('content_type', '')
            
            # Check path patterns
            for pattern in api_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    endpoints.append({
                        'path': path,
                        'status': result.get('status'),
                        'size': result.get('size'),
                        'content_type': content_type
                    })
                    break
            
            # Check content type
            if 'json' in content_type.lower() or 'xml' in content_type.lower():
                if path not in [e['path'] for e in endpoints]:
                    endpoints.append({
                        'path': path,
                        'status': result.get('status'),
                        'size': result.get('size'),
                        'content_type': content_type
                    })
        
        return endpoints
    
    def _analyze_endpoint(self, endpoint, scan_results):
        """Analyze an API endpoint"""
        path = endpoint['path']
        
        # Determine API type
        api_type = 'REST'
        if 'graphql' in path.lower():
            api_type = 'GraphQL'
        elif 'soap' in path.lower():
            api_type = 'SOAP'
        
        endpoint_info = {
            'path': path,
            'type': api_type,
            'status': endpoint['status'],
            'content_type': endpoint['content_type'],
            'methods': ['GET'],  # Default
            'authentication': 'Unknown',
            'issues': []
        }
        
        # Check authentication
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
        """Check for common API security issues"""
        issues = []
        
        for endpoint in self.results['endpoints']:
            path = endpoint['path']
            
            # Check for sensitive parameters in URL
            if any(param in path.lower() for param in ['api_key', 'token', 'secret', 'password']):
                issues.append({
                    'severity': 'High',
                    'issue': 'Sensitive parameter in URL',
                    'path': path,
                    'description': 'API credentials should not be passed in URL'
                })
            
            # Check for version disclosure
            if re.search(r'/v\d+/', path):
                issues.append({
                    'severity': 'Low',
                    'issue': 'API version disclosed',
                    'path': path,
                    'description': 'API version number exposed in path'
                })
            
            # Check for no authentication
            if endpoint['authentication'] == 'None or weak':
                issues.append({
                    'severity': 'High',
                    'issue': 'No authentication required',
                    'path': path,
                    'description': 'API endpoint accessible without authentication'
                })
        
        self.results['security_issues'] = issues
        
        if issues:
            print(f"[!] Found {len(issues)} API security issues")
    
    def _check_documentation(self, scan_results):
        """Check for API documentation"""
        doc_patterns = [
            '/api/docs', '/api/documentation', '/swagger',
            '/api-docs', '/graphiql', '/graphql-playground'
        ]
        
        for result in scan_results.get('found', []):
            path = result.get('path', '')
            for pattern in doc_patterns:
                if pattern in path.lower():
                    self.results['documentation'].append({
                        'path': path,
                        'status': result.get('status')
                    })
                    print(f"[+] API documentation found: {path}")

class PluginManager:
    """Manages plugin loading and execution"""
    
    def __init__(self, plugin_names, args):
        self.plugin_names = plugin_names
        self.args = args
        self.plugins = []
        self.results = {}
    
    def load_plugins(self):
        """Load specified plugins"""
        available_plugins = {
            'wordpress': WordPressScanner,
            'api-scanner': APIScanner,
            'sensitive-files': SensitiveFileScanner
        }
        
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
        """Run all loaded plugins"""
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
        """Save plugin results to file"""
        with open(output_file, 'w') as f:
            json.dump(self.results, f, indent=2)
    
    def get_available_plugins(self):
        """Get list of available plugins"""
        return [
            ('wordpress', 'WordPress security and vulnerability scanner'),
            ('api-scanner', 'API endpoint discovery and security analysis'),
            ('sensitive-files', 'Sensitive file and configuration detector')
        ]