"""
Enhanced AI-powered path generation module
Improved prompts for better results
"""

import json
import os
import re
import time
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
    """Claude AI implementation with improved prompts"""
    
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("Claude API key not found. Set ANTHROPIC_API_KEY environment variable.")
        
        self.api_url = "https://api.anthropic.com/v1/messages"
        self.model = "claude-3-haiku-20240307"
        self.max_tokens = 2000
    
    def get_model_name(self):
        return "Claude 3 Haiku"
    
    def generate_paths(self, context: Dict[str, Any]) -> List[str]:
        """Generate paths using Claude AI with improved prompts"""
        
        prompt = self._build_enhanced_prompt(context)
        
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01"
        }
        
        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": 0.7,
            "system": """You are an expert penetration tester specializing in web application security and directory enumeration.
Your task is to generate likely hidden paths and directories for security testing.

CRITICAL RULES:
1. Return ONLY a JSON array of paths
2. Each path MUST start with /
3. NO explanations, NO markdown, NO extra text
4. Focus on realistic, high-probability paths
5. Consider the target's technology stack and keywords

Example output format:
["/admin","/api/v1/users","/.env","/backup.zip"]""",
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }
        
        try:
            print(f"[*] Calling Claude API...")
            response = requests.post(self.api_url, headers=headers, json=payload, timeout=60)
            
            # Error handling
            if response.status_code == 401:
                print(f"[-] Invalid API key")
                raise Exception("Claude API: Invalid API key")
            elif response.status_code == 402:
                print("[-] No credits available")
                raise Exception("Claude API: Payment required - add API credits at https://console.anthropic.com/settings/billing")
            elif response.status_code == 429:
                raise Exception("Claude API: Rate limited")
            elif response.status_code != 200:
                error_text = response.text[:200]
                raise Exception(f"Claude API Error {response.status_code}: {error_text}")
            
            data = response.json()
            
            if 'content' in data and len(data['content']) > 0:
                content = data['content'][0]['text']
                print(f"[+] Received {len(content)} characters from Claude")
                return self._parse_response(content)
            else:
                raise Exception("No content in Claude response")
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Claude API connection error: {str(e)}")
        except Exception as e:
            raise Exception(f"Claude API error: {str(e)}")
    
    def _build_enhanced_prompt(self, context: Dict[str, Any]) -> str:
        """Build enhanced prompt for Claude with better structure"""
        
        url = context.get('url', 'Unknown')
        tech = ', '.join(context.get('tech', [])[:5]) if context.get('tech') else 'Unknown'
        keywords = ', '.join(context.get('keywords', [])[:20]) if context.get('keywords') else 'None'
        
        return f"""Generate hidden directory paths for penetration testing of this target:

TARGET INFORMATION:
- URL: {url}
- Technologies: {tech}
- Keywords: {keywords}

REQUIREMENTS:
Generate 40-80 realistic paths that include:

1. ADMIN INTERFACES:
   - Admin panels, dashboards, control panels
   - Login pages, authentication endpoints
   - Management interfaces

2. API ENDPOINTS:
   - REST API paths (/api, /api/v1, /api/v2)
   - GraphQL endpoints
   - WebSocket connections
   - Internal API routes

3. CONFIGURATION FILES:
   - Environment files (.env, .env.local, .env.production)
   - Config files (config.php, config.json, settings.py)
   - Database configs

4. BACKUP & SENSITIVE FILES:
   - Backup archives (.zip, .tar.gz, .sql, .bak)
   - Database dumps
   - Source code backups
   - Old versions

5. DEVELOPMENT & DEBUG:
   - Test pages, debug interfaces
   - Development environments
   - PHPInfo, server info pages
   - Error logs, debug logs

6. VERSION CONTROL:
   - .git directories and files
   - .svn directories
   - Source control artifacts

7. TECHNOLOGY-SPECIFIC PATHS:
   Based on detected technologies: {tech}
   - Framework-specific paths
   - CMS-specific directories
   - Platform-specific endpoints

8. KEYWORD-BASED PATHS:
   Based on keywords: {keywords}
   - Related admin paths
   - Keyword variations
   - Common combinations

OUTPUT:
Return ONLY a valid JSON array of paths. Each path must start with /.
Example: ["/admin","/api/v1","/.env"]

Generate the JSON array now:"""
    
    def _parse_response(self, text: str) -> List[str]:
        """Parse Claude response with improved error handling"""
        if not text:
            return []
        
        print("[*] Parsing Claude response...")
        
        try:
            # Remove markdown code blocks
            text = re.sub(r'```(json)?|```', '', text).strip()
            
            # Try to find JSON array
            json_match = re.search(r'\[.*\]', text, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
            else:
                data = json.loads(text)
            
            # Handle dict or list
            if isinstance(data, dict):
                for key in ['paths', 'directories', 'results', 'data']:
                    if key in data and isinstance(data[key], list):
                        data = data[key]
                        break
            
            # Clean and validate paths
            cleaned = []
            if isinstance(data, list):
                for path in data:
                    if isinstance(path, str):
                        path = path.strip()
                        # Ensure path starts with /
                        if not path.startswith('/'):
                            path = '/' + path
                        # Remove double slashes
                        path = re.sub(r'/+', '/', path)
                        # Validate path
                        if len(path) > 1 and len(path) < 200:
                            cleaned.append(path)
            
            print(f"[+] Parsed {len(cleaned)} valid paths")
            return list(set(cleaned))
            
        except Exception as e:
            print(f"[!] Parse error: {e}")
            # Regex fallback
            paths = re.findall(r'["\'](/[^"\'\s]+)["\']', text)
            return list(set(paths))

class OpenAIModel(BaseAIModel):
    """OpenAI GPT implementation"""
    
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key not found. Set OPENAI_API_KEY environment variable.")
        
        self.api_url = "https://api.openai.com/v1/chat/completions"
        self.model = "gpt-3.5-turbo"
        self.max_tokens = 1500
    
    def get_model_name(self):
        return f"OpenAI {self.model}"
    
    def generate_paths(self, context: Dict[str, Any]) -> List[str]:
        """Generate paths using OpenAI"""
        
        prompt = self._build_prompt(context)
        
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }
        
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a pentesting expert. Generate ONLY a JSON array of directory paths starting with /. No explanations."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "max_tokens": self.max_tokens
        }
        
        try:
            print("[*] Calling OpenAI API...")
            response = requests.post(self.api_url, headers=headers, json=payload, timeout=60)
            
            if response.status_code != 200:
                error = response.json().get('error', {}).get('message', 'Unknown error')
                raise Exception(f"OpenAI Error: {error}")
            
            data = response.json()
            content = data['choices'][0]['message']['content']
            print(f"[+] Received response from OpenAI")
            return self._parse_response(content)
            
        except Exception as e:
            raise Exception(f"OpenAI API error: {str(e)}")
    
    def _build_prompt(self, context: Dict[str, Any]) -> str:
        url = context.get('url', '')
        tech = ', '.join(context.get('tech', [])[:5])
        keywords = ', '.join(context.get('keywords', [])[:10])
        
        return f"""Generate hidden paths for penetration testing.

Website: {url}
Technologies: {tech}
Keywords: {keywords}

Generate 40-60 paths including:
- Admin panels and dashboards
- API endpoints
- Config and backup files
- Technology-specific paths

Return ONLY a JSON array of paths. Each path must start with /.
Example: ["/admin", "/api/v1", "/.env"]"""
    
    def _parse_response(self, text: str) -> List[str]:
        try:
            # Remove markdown
            text = re.sub(r'```(json)?|```', '', text).strip()
            
            # Find JSON array
            json_match = re.search(r'\[.*\]', text, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
            else:
                data = json.loads(text)
            
            if isinstance(data, dict) and "paths" in data:
                paths = data["paths"]
            elif isinstance(data, list):
                paths = data
            else:
                paths = []
            
            cleaned = []
            for path in paths:
                if isinstance(path, str):
                    path = path.strip()
                    if not path.startswith('/'):
                        path = '/' + path
                    if len(path) > 1:
                        cleaned.append(path)
            
            return list(set(cleaned))
        except:
            # Fallback regex
            paths = re.findall(r'["\'](/[^"\'\s]+)["\']', text)
            return list(set(paths))

class LocalModel(BaseAIModel):
    """Enhanced local pattern-based model"""
    
    def __init__(self):
        pass
    
    def get_model_name(self):
        return "Local Pattern Matcher (Enhanced)"
    
    def generate_paths(self, context: Dict[str, Any]) -> List[str]:
        """Generate paths using enhanced local patterns"""
        paths = {
            # Admin interfaces
            '/admin', '/administrator', '/admin/login', '/admin/index', '/admin/dashboard',
            '/panel', '/control', '/console', '/manager', '/backend', '/backoffice',
            '/login', '/signin', '/auth', '/authenticate', '/session',
            
            # API endpoints
            '/api', '/api/v1', '/api/v2', '/api/v3', '/rest', '/restful',
            '/graphql', '/graphiql', '/api/docs', '/api/swagger', '/swagger',
            '/api/users', '/api/admin', '/api/auth', '/api/login',
            
            # Configuration
            '/.env', '/.env.local', '/.env.production', '/.env.development',
            '/config', '/config.php', '/config.json', '/config.yml', '/settings',
            '/configuration', '/configure', '/.htaccess', '/.htpasswd',
            '/web.config', '/app.config', '/database.yml',
            
            # Backups
            '/backup', '/backups', '/backup.zip', '/backup.tar.gz', '/backup.sql',
            '/db_backup', '/dump', '/dump.sql', '/database.sql', '/old', '/oldsite',
            
            # Development
            '/dev', '/development', '/test', '/testing', '/debug', '/temp', '/tmp',
            '/phpinfo.php', '/info.php', '/test.php', '/debug.php',
            
            # Version control
            '/.git', '/.git/config', '/.git/HEAD', '/.svn', '/.hg',
            
            # Logs
            '/logs', '/log', '/error_log', '/access_log', '/error.log', '/access.log',
            '/debug.log', '/application.log',
            
            # Common files
            '/robots.txt', '/sitemap.xml', '/humans.txt', '/security.txt',
            '/.well-known', '/.well-known/security.txt',
            
            # Uploads
            '/uploads', '/files', '/media', '/images', '/documents', '/attachments',
            '/download', '/downloads',
            
            # Scripts
            '/cgi-bin', '/scripts', '/js', '/javascript', '/css', '/assets'
        }
        
        # Add tech-specific paths
        for tech in context.get('tech', []):
            tech_lower = tech.lower()
            
            if 'wordpress' in tech_lower:
                paths.update([
                    '/wp-admin', '/wp-login.php', '/wp-content', '/wp-includes',
                    '/wp-json', '/xmlrpc.php', '/wp-config.php', '/wp-config.php.bak',
                    '/wp-content/plugins', '/wp-content/themes', '/wp-content/uploads'
                ])
            
            if 'php' in tech_lower:
                paths.update([
                    '/phpinfo.php', '/info.php', '/test.php', '/shell.php',
                    '/upload.php', '/admin.php', '/index.php'
                ])
            
            if 'laravel' in tech_lower:
                paths.update([
                    '/storage', '/storage/logs', '/.env', '/artisan',
                    '/vendor', '/bootstrap/cache'
                ])
            
            if 'django' in tech_lower or 'python' in tech_lower:
                paths.update([
                    '/admin/', '/accounts', '/api', '/.env', '/settings.py',
                    '/manage.py', '/requirements.txt'
                ])
            
            if 'node' in tech_lower or 'express' in tech_lower:
                paths.update([
                    '/.env', '/package.json', '/node_modules', '/dist', '/build'
                ])
            
            if 'react' in tech_lower or 'vue' in tech_lower or 'angular' in tech_lower:
                paths.update([
                    '/build', '/dist', '/public', '/src', '/.env'
                ])
            
            if 'java' in tech_lower:
                paths.update([
                    '/admin/console', '/manager', '/jmx-console', '/web-console',
                    '/WEB-INF', '/WEB-INF/web.xml'
                ])
            
            if 'asp' in tech_lower or '.net' in tech_lower:
                paths.update([
                    '/admin', '/Admin', '/admin.aspx', '/login.aspx',
                    '/web.config', '/Web.config'
                ])
        
        # Add keyword-based paths
        for kw in context.get('keywords', [])[:15]:
            if len(kw) > 2 and kw.isalnum():
                paths.update([
                    f'/{kw}', 
                    f'/{kw}/admin', 
                    f'/{kw}/api',
                    f'/{kw}.php',
                    f'/{kw}.html'
                ])
        
        return sorted(list(paths))

class AIPathGenerator:
    """Main AI path generator with improved error handling"""
    
    def __init__(self, model="local", api_key=None):
        self.model_name = model.lower()
        
        try:
            if self.model_name == "claude":
                self.model = ClaudeAIModel(api_key)
            elif self.model_name == "openai":
                self.model = OpenAIModel(api_key)
            else:
                self.model = LocalModel()
                self.model_name = "local"
            
            print(f"[+] Using {self.model.get_model_name()}")
            
        except ValueError as e:
            print(f"[!] {str(e)}")
            print("[*] Falling back to local model")
            self.model = LocalModel()
            self.model_name = "local"
    
    def generate_paths(self, recon_data, depth=1, max_paths=500):
        """Generate paths with context"""
        print(f"[*] Generating paths using {self.model.get_model_name()}...")
        start = time.time()
        
        try:
            context = {
                'url': recon_data.get('url', ''),
                'keywords': recon_data.get('keywords', [])[:20],
                'tech': recon_data.get('tech', []),
                'links': recon_data.get('links', [])[:10],
                'scripts': recon_data.get('scripts', [])[:10],
                'forms': recon_data.get('forms', [])[:5]
            }
            
            paths = self.model.generate_paths(context)
            
            duration = time.time() - start
            print(f"[+] Generated {len(paths)} paths in {duration:.2f}s")
            
            if len(paths) > max_paths:
                paths = paths[:max_paths]
            
            return sorted(list(set(paths)))
            
        except Exception as e:
            print(f"[-] Error: {e}")
            print("[*] Using local fallback...")
            fallback = LocalModel()
            return fallback.generate_paths(context)