"""
Enhanced AI-powered path generation module
Multiple AI models and prompt templates
"""

import json
import os
import re
from typing import List, Dict, Any
import requests
from abc import ABC, abstractmethod

class BaseAIModel(ABC):
    """Abstract base class for AI models"""
    
    @abstractmethod
    def generate_paths(self, context: Dict[str, Any]) -> List[str]:
        pass
    
    @abstractmethod
    def get_model_name(self) -> str:
        pass

class ClaudeAIModel(BaseAIModel):
    """Claude AI implementation"""
    
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.api_url = "https://api.anthropic.com/v1/messages"
        self.model = "claude-3-sonnet-20240229"
    
    def get_model_name(self):
        return "Claude 3 Sonnet"
    
    def generate_paths(self, context: Dict[str, Any]) -> List[str]:
        """Generate paths using Claude AI"""
        
        prompt = self._build_prompt(context)
        
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01"
        }
        
        payload = {
            "model": self.model,
            "max_tokens": 4000,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.7
        }
        
        try:
            response = requests.post(self.api_url, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            content = data['content'][0]['text']
            return self._parse_response(content)
            
        except Exception as e:
            raise Exception(f"Claude API error: {str(e)}")
    
    def _build_prompt(self, context: Dict[str, Any]) -> str:
        """Build detailed prompt for Claude"""
        
        return f"""As a senior penetration tester and web security expert, analyze this website reconnaissance data and generate the most likely hidden paths.

WEBSITE ANALYSIS:
- URL: {context['url']}
- Technologies: {', '.join(context['tech'])}
- Keywords Found: {', '.join(context['keywords'][:30])}
- Links Discovered: {len(context['links'])} links
- Scripts Found: {len(context['scripts'])} JavaScript/CSS files
- Forms Found: {len(context['forms'])} forms
- Status Code: {context.get('status_code', 'Unknown')}
- Server: {context.get('server', 'Unknown')}

SCAN CONTEXT:
- Scan Type: Directory/File Enumeration
- Purpose: Security Assessment
- Priority: High-value targets first

GENERATION GUIDELINES:
1. Generate paths for admin interfaces and control panels
2. Include API endpoints and webservices
3. List configuration files and backups
4. Consider technology-specific paths
5. Include common hidden directories
6. Add debug/testing endpoints
7. Include upload/download directories
8. List database/admin interfaces
9. Include cache and session directories
10. Add version control system paths

PATH CATEGORIES TO COVER:
A) ADMINISTRATION:
   - Login panels, dashboards, admin consoles
   - CMS-specific admin paths
   - Server administration interfaces

B) API & WEBSERVICES:
   - REST API endpoints
   - GraphQL interfaces
   - SOAP/WSDL endpoints
   - Webhook endpoints

C) CONFIGURATION & SECURITY:
   - Environment/config files
   - Security certificates
   - Backup/archive files
   - Log files

D) DEVELOPMENT & DEBUG:
   - Debug interfaces
   - Testing endpoints
   - Developer tools
   - Documentation

E) FILE & STORAGE:
   - Upload directories
   - Media libraries
   - Static resources
   - Cache directories

FORMAT REQUIREMENTS:
- Return ONLY a JSON array of paths
- Each path must start with /
- Include paths for different HTTP methods (GET, POST)
- Prioritize paths by likelihood
- Include both directories and files

SAMPLE OUTPUT FORMAT:
["/admin/login.php", "/api/v1/users", "/.env", "/wp-admin", "/debug"]

Now generate the JSON array of paths:"""

    def _parse_response(self, text: str) -> List[str]:
        """Parse AI response and extract paths"""
        # Clean response
        text = text.strip()
        text = re.sub(r'```(json)?|```', '', text)
        
        try:
            paths = json.loads(text)
            if isinstance(paths, list):
                # Validate and clean paths
                valid_paths = []
                for path in paths:
                    if isinstance(path, str) and path.startswith('/'):
                        valid_paths.append(path)
                return valid_paths
        except json.JSONDecodeError:
            pass
        
        # Fallback: extract paths using regex
        paths = re.findall(r'["\'](/[^"\'\s]+)["\']', text)
        return list(set(paths))

class OpenAIModel(BaseAIModel):
    """OpenAI GPT implementation"""
    
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.api_url = "https://api.openai.com/v1/chat/completions"
        self.model = "gpt-4-turbo-preview"
    
    def get_model_name(self):
        return "GPT-4 Turbo"
    
    def generate_paths(self, context: Dict[str, Any]) -> List[str]:
        """Generate paths using OpenAI GPT"""
        
        prompt = self._build_prompt(context)
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a web security expert generating directory/file paths for penetration testing."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "max_tokens": 2000
        }
        
        try:
            response = requests.post(self.api_url, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            content = data['choices'][0]['message']['content']
            return self._parse_response(content)
            
        except Exception as e:
            raise Exception(f"OpenAI API error: {str(e)}")
    
    def _build_prompt(self, context: Dict[str, Any]) -> str:
        """Build prompt for OpenAI"""
        return f"""Generate hidden directory and file paths for penetration testing based on this reconnaissance:

Website: {context['url']}
Technologies: {', '.join(context['tech'])}
Keywords: {', '.join(context['keywords'][:20])}
Discovered links: {len(context['links'])}
Server headers: {context.get('server', 'Unknown')}

Generate a JSON array of the most likely hidden paths, prioritizing:
1. Admin interfaces and login panels
2. API endpoints and web services
3. Configuration files (.env, config.*)
4. Backup files and archives
5. Technology-specific paths
6. Debug and testing interfaces
7. Upload directories
8. Database interfaces

Return ONLY a JSON array:"""

class LocalModel(BaseAIModel):
    """Local/offline AI model using pattern matching"""
    
    def __init__(self):
        self.patterns = self._load_patterns()
    
    def get_model_name(self):
        return "Local Pattern Matcher"
    
    def generate_paths(self, context: Dict[str, Any]) -> List[str]:
        """Generate paths using pattern matching"""
        paths = []
        
        # Technology-specific patterns
        tech_patterns = {
            'WordPress': ['/wp-', '/xmlrpc', '/feed', '/comments'],
            'Django': ['/admin/', '/static/', '/media/', '/api/'],
            'Laravel': ['/storage/', '/bootstrap/', '/public/'],
            'PHP': ['/php', '/cgi-bin/', '/test.'],
            'ASP.NET': ['/aspx', '/webresource.axd', '/trace.axd']
        }
        
        # Add technology-specific paths
        for tech in context['tech']:
            for key, patterns in tech_patterns.items():
                if key.lower() in tech.lower():
                    paths.extend(patterns)
        
        # Keyword-based paths
        for keyword in context['keywords'][:15]:
            if len(keyword) > 2:
                paths.extend([
                    f'/{keyword}',
                    f'/{keyword}/admin',
                    f'/{keyword}.php',
                    f'/{keyword}.json',
                    f'/{keyword}/api',
                    f'/admin/{keyword}'
                ])
        
        # Common paths database
        common_paths = [
            # Admin interfaces
            '/admin', '/administrator', '/login', '/signin', '/dashboard',
            '/panel', '/console', '/manager', '/sysadmin', '/root',
            
            # API endpoints
            '/api', '/api/v1', '/api/v2', '/api/v3', '/graphql',
            '/rest', '/soap', '/wsdl', '/webhook', '/webapi',
            
            # Configuration
            '/.env', '/config.php', '/config.json', '/settings',
            '/configuration', '/.config', '/secrets', '/credentials',
            
            # Backup files
            '/backup', '/backups', '/backup.zip', '/backup.tar.gz',
            '/dump.sql', '/database.sql', '/backup.sql',
            
            # Debug/Development
            '/debug', '/test', '/testing', '/dev', '/development',
            '/stage', '/staging', '/beta', '/alpha',
            
            # Files and uploads
            '/uploads', '/files', '/downloads', '/media',
            '/images', '/assets', '/static', '/public',
            
            # Logs
            '/logs', '/log', '/error_log', '/access_log',
            '/debug.log', '/app.log', '/system.log'
        ]
        
        paths.extend(common_paths)
        return list(set(paths))
    
    def _load_patterns(self):
        """Load path patterns from file"""
        # Could load from external patterns file
        return {}

class AIPathGenerator:
    """Enhanced AI path generator with multiple models"""
    
    def __init__(self, model="claude", api_key=None):
        self.model_name = model
        self.api_key = api_key
        
        # Initialize selected model
        if model == "claude":
            self.model = ClaudeAIModel(api_key)
        elif model == "openai":
            self.model = OpenAIModel(api_key)
        elif model == "local":
            self.model = LocalModel()
        else:
            raise ValueError(f"Unsupported model: {model}")
    
    def generate_paths(self, recon_data, depth=1, max_paths=500):
        """Generate intelligent paths with depth consideration"""
        
        # Build comprehensive context
        context = self._build_context(recon_data)
        
        try:
            # Generate base paths
            paths = self.model.generate_paths(context)
            
            # Apply depth if needed
            if depth > 1:
                paths = self._apply_depth(paths, depth)
            
            # Limit number of paths
            if len(paths) > max_paths:
                paths = paths[:max_paths]
            
            return paths
            
        except Exception as e:
            print(f"AI generation warning: {e}")
            # Fallback to local model
            fallback = LocalModel()
            return fallback.generate_paths(context)
    
    def _build_context(self, data):
        """Build detailed context for AI"""
        
        return {
            'url': data['url'],
            'keywords': data['keywords'][:50] if data['keywords'] else [],
            'tech': data['tech'],
            'links': data['links'][:20] if data['links'] else [],
            'scripts': data['scripts'][:20] if data['scripts'] else [],
            'forms': data['forms'][:10] if data['forms'] else [],
            'server': data.get('headers', {}).get('Server', 'Unknown'),
            'status_code': data.get('status_code', 'Unknown'),
            'content_type': data.get('headers', {}).get('Content-Type', 'Unknown')
        }
    
    def _apply_depth(self, paths, depth):
        """Apply directory depth to paths"""
        enhanced_paths = []
        
        for path in paths:
            enhanced_paths.append(path)
            
            # For directories, add subdirectories
            if depth > 1 and not path.endswith(('.php', '.html', '.js', '.txt', '.json', '.xml')):
                for i in range(1, depth):
                    subdir = f"{path}/subdir{i}" if not path.endswith('/') else f"{path}subdir{i}"
                    enhanced_paths.append(subdir)
                    
                    # Add files in subdirectories
                    enhanced_paths.extend([
                        f"{subdir}/index.php",
                        f"{subdir}/index.html",
                        f"{subdir}/config.php"
                    ])
        
        return enhanced_paths

# Advanced prompt templates for different scenarios
PROMPT_TEMPLATES = {
    "comprehensive": """Generate comprehensive hidden paths for {url}
Technologies: {tech}
Focus on: admin panels, API endpoints, config files, backups, uploads, logs, debug interfaces""",
    
    "aggressive": """Generate aggressive penetration testing paths for {url}
Include: sensitive files, configuration files, backup archives, database dumps, debug endpoints""",
    
    "stealthy": """Generate stealthy hidden paths for {url}
Focus on: common paths, standard installations, default locations, common misconfigurations""",
    
    "api_focused": """Generate API-related paths for {url}
Include: REST endpoints, GraphQL, webhooks, API documentation, API management interfaces""",
    
    "cms_specific": """Generate CMS-specific paths for {url} running {tech}
Include: admin paths, plugin directories, theme files, configuration, backup locations"""
}

def get_prompt_template(template_name, context):
    """Get formatted prompt template"""
    if template_name in PROMPT_TEMPLATES:
        return PROMPT_TEMPLATES[template_name].format(**context)
    return PROMPT_TEMPLATES["comprehensive"].format(**context)