"""
Plugin system for extending AIBuster functionality
"""

import importlib
import inspect
from typing import Dict, List, Any
from abc import ABC, abstractmethod
import re
import json

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

class WordpressScanner(Plugin):
    """WordPress-specific scanner plugin"""
    
    def __init__(self):
        self.name = "WordPress Scanner"
        self.results = {
            'version': None,
            'plugins': [],
            'themes': [],
            'users': [],
            'vulnerabilities': []
        }
    
    def get_name(self):
        return self.name
    
    def get_description(self):
        return "Scans WordPress sites for version, plugins, themes, and vulnerabilities"
    
    def run(self, recon_data, scan_results):
        """Run WordPress scan"""
        
        # Check if site is WordPress
        if not self._is_wordpress(recon_data):
            return {'error': 'Not a WordPress site'}
        
        # Gather WordPress information
        self._scan_wordpress(recon_data, scan_results)
        
        return self.results
    
    def get_results(self):
        return self.results
    
    def _is_wordpress(self, recon_data):
        """Check if site is WordPress"""
        tech = recon_data.get('tech', [])
        content = recon_data.get('content', '')
        
        wordpress_indicators = [
            'WordPress' in tech,
            'wp-content' in content,
            'wp-includes' in content,
            '/wp-admin' in str(recon_data.get('links', [])),
            '/wp-json' in str(recon_data.get('links', []))
        ]
        
        return any(wordpress_indicators)
    
    def _scan_wordpress(self, recon_data, scan_results):
        """Scan WordPress site"""
        url = recon_data.get('url', '')
        
        # Check common WordPress paths
        wp_paths = [
            '/wp-content/plugins/',
            '/wp-content/themes/',
            '/wp-json/wp/v2/users',
            '/readme.html',
            '/license.txt',
            '/wp-login.php'
        ]
        
        # Check for version
        for result in scan_results.get('found', []):
            if 'readme.html' in result.get('path', ''):
                self.results['version'] = self._extract_version(result)
        
        # Scan for plugins and themes
        self._scan_plugins_themes(scan_results)
        
        # Check for user enumeration
        self._check_user_enumeration(recon_data)
    
    def _extract_version(self, result):
        """Extract WordPress version from readme"""
        # Simplified version extraction
        return "Unknown"
    
    def _scan_plugins_themes(self, scan_results):
        """Scan for installed plugins and themes"""
        plugins = set()
        themes = set()
        
        for result in scan_results.get('found', []):
            path = result.get('path', '')
            
            # Extract plugin names
            if '/wp-content/plugins/' in path:
                plugin_name = path.split('/wp-content/plugins/')[1].split('/')[0]
                if plugin_name:
                    plugins.add(plugin_name)
            
            # Extract theme names
            if '/wp-content/themes/' in path:
                theme_name = path.split('/wp-content/themes/')[1].split('/')[0]
                if theme_name:
                    themes.add(theme_name)
        
        self.results['plugins'] = list(plugins)
        self.results['themes'] = list(themes)
    
    def _check_user_enumeration(self, recon_data):
        """Check for user enumeration vulnerability"""
        # Check if user enumeration is possible via REST API
        api_url = recon_data['url'].rstrip('/') + '/wp-json/wp/v2/users'
        # In real implementation, would make HTTP request
        self.results['users'] = ['admin']  # Placeholder

class APIScanner(Plugin):
    """API endpoint scanner plugin"""
    
    def __init__(self):
        self.name = "API Scanner"
        self.results = {
            'endpoints': [],
            'methods': {},
            'parameters': [],
            'security_issues': []
        }
    
    def get_name(self):
        return self.name
    
    def get_description(self):
        return "Scans for API endpoints and analyzes them for security issues"
    
    def run(self, recon_data, scan_results):
        """Run API scan"""
        
        # Find API endpoints
        api_endpoints = self._find_api_endpoints(scan_results)
        
        # Analyze endpoints
        for endpoint in api_endpoints:
            endpoint_info = self._analyze_endpoint(endpoint, recon_data)
            if endpoint_info:
                self.results['endpoints'].append(endpoint_info)
        
        # Check for common security issues
        self._check_security_issues()
        
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
            r'/rest/',
            r'/json/',
            r'/xml/',
            r'/soap',
            r'/webhook',
            r'/webapi',
            r'/services/',
            r'/ws/'
        ]
        
        for result in scan_results.get('found', []):
            path = result.get('path', '')
            for pattern in api_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    endpoints.append(path)
                    break
        
        return list(set(endpoints))
    
    def _analyze_endpoint(self, endpoint, recon_data):
        """Analyze an API endpoint"""
        # In real implementation, would make HTTP requests to analyze
        return {
            'path': endpoint,
            'methods': ['GET'],  # Placeholder
            'parameters': [],
            'description': 'API endpoint'
        }
    
    def _check_security_issues(self):
        """Check for common API security issues"""
        issues = []
        
        for endpoint in self.results['endpoints']:
            path = endpoint['path']
            
            # Check for common issues
            if 'api_key' in path or 'token' in path:
                issues.append(f"Potential sensitive parameter in URL: {path}")
            
            if any(ext in path for ext in ['.json', '.xml']):
                issues.append(f"Direct data access: {path}")
        
        self.results['security_issues'] = issues

class SensitiveFileScanner(Plugin):
    """Sensitive file scanner plugin"""
    
    def __init__(self):
        self.name = "Sensitive File Scanner"
        self.results = {
            'sensitive_files': [],
            'backup_files': [],
            'config_files': [],
            'log_files': []
        }
    
    def get_name(self):
        return self.name
    
    def get_description(self):
        return "Scans for sensitive files like backups, configs, and logs"
    
    def run(self, recon_data, scan_results):
        """Scan for sensitive files"""
        
        sensitive_patterns = {
            'sensitive_files': [
                r'\.env$',
                r'config\.(php|json|yml|yaml|xml)$',
                r'\.git/config$',
                r'\.htaccess$',
                r'\.htpasswd$',
                r'web\.config$',
                r'\.DS_Store$'
            ],
            'backup_files': [
                r'\.bak$',
                r'\.old$',
                r'\.backup$',
                r'backup\.',
                r'dump\.',
                r'\.tar\.gz$',
                r'\.zip$',
                r'_backup'
            ],
            'config_files': [
                r'config/',
                r'settings/',
                r'configuration/',
                r'\.config/'
            ],
            'log_files': [
                r'\.log$',
                r'logs/',
                r'error_log',
                r'access_log',
                r'debug\.log$'
            ]
        }
        
        for result in scan_results.get('found', []):
            path = result.get('path', '')
            
            for category, patterns in sensitive_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, path, re.IGNORECASE):
                        self.results[category].append({
                            'path': path,
                            'status': result.get('status'),
                            'size': result.get('size')
                        })
                        break
        
        return self.results
    
    def get_results(self):
        return self.results

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
            'wordpress': WordpressScanner,
            'api-scanner': APIScanner,
            'sensitive-files': SensitiveFileScanner
            # Add more plugins here
        }
        
        for name in self.plugin_names:
            if name in available_plugins:
                plugin_class = available_plugins[name]
                plugin_instance = plugin_class()
                self.plugins.append(plugin_instance)
            else:
                print(f"Warning: Plugin '{name}' not found")
    
    def run_plugins(self, recon_data, scan_results):
        """Run all loaded plugins"""
        results = {}
        
        for plugin in self.plugins:
            try:
                print(f"Running plugin: {plugin.get_name()}")
                plugin_result = plugin.run(recon_data, scan_results)
                results[plugin.get_name()] = plugin_result
            except Exception as e:
                print(f"Error running plugin {plugin.get_name()}: {str(e)}")
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
            ('wordpress', 'WordPress vulnerability scanner'),
            ('api-scanner', 'API endpoint discovery and analysis'),
            ('sensitive-files', 'Sensitive file detector'),
            # Add more plugin descriptions
        ]

# Plugin development utilities
def create_plugin_template(plugin_name):
    """Create a new plugin template"""
    template = f'''"""
{plugin_name} Plugin for AIBuster
"""

from plugins import Plugin
import re

class {plugin_name.replace('-', '').title().replace(' ', '')}Plugin(Plugin):
    """{plugin_name} plugin"""
    
    def __init__(self):
        self.name = "{plugin_name.title()} Plugin"
        self.results = {{}}
    
    def get_name(self):
        return self.name
    
    def get_description(self):
        return "Description of {plugin_name} plugin"
    
    def run(self, recon_data, scan_results):
        """
        Run the plugin
        
        Args:
            recon_data: Reconnaissance data
            scan_results: Scan results
            
        Returns:
            Dictionary with plugin results
        """
        # Your plugin logic here
        self.results['status'] = 'completed'
        return self.results
    
    def get_results(self):
        return self.results

# For testing
if __name__ == "__main__":
    plugin = {plugin_name.replace('-', '').title().replace(' ', '')}Plugin()
    print(f"Plugin: {{plugin.get_name()}}")
    print(f"Description: {{plugin.get_description()}}")
'''
    
    filename = f"plugin_{plugin_name.lower().replace(' ', '_')}.py"
    with open(filename, 'w') as f:
        f.write(template)
    
    print(f"Plugin template created: {filename}")
    return filename