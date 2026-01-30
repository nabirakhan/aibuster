import json
import os
import re
import time
from typing import List, Dict, Any
import requests
from abc import ABC, abstractmethod

class BaseAIModel(ABC):
    @abstractmethod
    def generate_paths(self, context: Dict[str, Any]) -> List[str]:
        pass
    @abstractmethod
    def get_model_name(self) -> str:
        pass

class ClaudeAIModel(BaseAIModel):
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("Claude API key not found. Set ANTHROPIC_API_KEY environment variable.")
        self.api_url = "https://api.anthropic.com/v1/messages"
        self.model = "claude-3-haiku-20240307"
        self.max_tokens = 2500
    
    def get_model_name(self):
        return "Claude 3 Haiku"
    
    def generate_paths(self, context: Dict[str, Any]) -> List[str]:
        prompt = self._build_enhanced_prompt(context)
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01"
        }
        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": 0.8,
            "system": """You are an elite penetration testing AI specializing in web application security, directory enumeration, and vulnerability assessment. Your expertise includes:
- Deep knowledge of web frameworks, CMSs, and application architectures
- Understanding of common security misconfigurations and exposed endpoints
- Experience with REST APIs, GraphQL, SOAP, and modern web technologies
- Familiarity with backup patterns, version control artifacts, and sensitive files

CRITICAL OUTPUT RULES:
1. Return ONLY a valid JSON array of paths - no explanations, no markdown formatting
2. Each path MUST start with /
3. Generate 60-100 highly relevant, realistic paths based on the target context
4. Prioritize paths likely to exist based on detected technologies and keywords
5. Include creative variations and uncommon but realistic paths
6. Focus on security-relevant endpoints (admin, API, configs, backups, sensitive files)

Example output format (and ONLY this format):
["/admin","/api/v1/users","/.env","/backup.zip","/wp-admin","/graphql"]""",
            "messages": [{"role": "user", "content": prompt}]
        }
        try:
            print(f"[*] Calling Claude API...")
            response = requests.post(self.api_url, headers=headers, json=payload, timeout=60)
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
        url = context.get('url', 'Unknown')
        tech = ', '.join(context.get('tech', [])[:8]) if context.get('tech') else 'Unknown'
        keywords = ', '.join(context.get('keywords', [])[:25]) if context.get('keywords') else 'None'
        return f"""Generate comprehensive hidden directory paths for penetration testing:

TARGET ANALYSIS:
- URL: {url}
- Detected Technologies: {tech}
- Extracted Keywords: {keywords}

Generate 60-100 high-probability paths organized by category:

1. ADMIN & AUTHENTICATION (15-20 paths):
   - Admin panels: /admin, /administrator, /admin-panel, /control-panel, /dashboard, /admin/login
   - Login endpoints: /login, /signin, /auth, /authenticate, /user/login, /account/login
   - Management: /manager, /console, /backend, /backoffice, /administration

2. API ENDPOINTS (15-20 paths):
   - REST APIs: /api, /api/v1, /api/v2, /api/v3, /rest, /restapi, /api/auth, /api/users, /api/admin
   - GraphQL: /graphql, /graphiql, /graphql/playground, /api/graphql
   - WebSocket: /ws, /websocket, /socket.io
   - Internal APIs: /internal/api, /private/api, /api/internal

3. SENSITIVE CONFIGURATION (15-20 paths):
   - Environment files: /.env, /.env.local, /.env.production, /.env.backup, /.env.old, /.env.dev
   - Config files: /config, /config.php, /config.json, /config.yml, /configuration, /settings.json, /app.config
   - Database configs: /database.yml, /db.json, /database.php, /dbconfig.php
   - Web configs: /.htaccess, /.htpasswd, /web.config, /nginx.conf

4. BACKUPS & ARCHIVES (10-15 paths):
   - Backup files: /backup, /backups, /backup.zip, /backup.tar.gz, /backup.sql, /db_backup.sql
   - Archives: /archive, /archives, /old, /oldsite, /site-backup, /website.zip
   - Database dumps: /dump.sql, /database.sql, /mysqldump.sql, /db.dump
   - Source backups: /src.zip, /source.tar.gz, /www.zip

5. DEVELOPMENT & DEBUG (10-12 paths):
   - Dev environments: /dev, /development, /test, /testing, /staging, /qa, /sandbox
   - Debug pages: /debug, /debug.php, /phpinfo.php, /info.php, /test.php, /diagnostic
   - Temp files: /tmp, /temp, /cache, /_temp

6. VERSION CONTROL & CI/CD (8-10 paths):
   - Git: /.git, /.git/config, /.git/HEAD, /.git/logs, /.gitignore
   - SVN: /.svn, /.svn/entries
   - Others: /.hg, /.bzr, /.gitlab-ci.yml, /.github

7. TECHNOLOGY-SPECIFIC PATHS (Based on: {tech}):
   - Generate 10-15 paths specific to detected technologies
   - WordPress: /wp-admin, /wp-login.php, /wp-content/plugins, /wp-json, /xmlrpc.php
   - Laravel: /storage/logs, /artisan, /vendor, /.env
   - Django: /admin/, /accounts, /api, /media, /static
   - Node.js: /node_modules, /package.json, /package-lock.json
   - Shopify: /admin, /cart.json, /products.json, /collections.json, /checkout
   - React/Vue: /build, /dist, /public, /src
   - Java: /WEB-INF, /web.xml, /admin/console, /manager

8. KEYWORD-BASED PATHS (Based on: {keywords}):
   - Generate 8-12 paths using extracted keywords
   - Examples: /{keywords}, /{keywords}/admin, /{keywords}/api, /{keywords}.php

9. LOGS & MONITORING (5-8 paths):
   - /logs, /log, /error_log, /access_log, /error.log, /debug.log, /app.log, /application.log

10. COMMON ENDPOINTS (5-8 paths):
    - /robots.txt, /sitemap.xml, /.well-known/security.txt, /humans.txt, /ads.txt
    - /favicon.ico, /crossdomain.xml

Return ONLY the JSON array of paths. No explanations. No markdown. Just the array."""
    
    def _parse_response(self, text: str) -> List[str]:
        if not text:
            return []
        print("[*] Parsing Claude response...")
        try:
            text = re.sub(r'```(json)?|```', '', text).strip()
            json_match = re.search(r'\[.*\]', text, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
            else:
                data = json.loads(text)
            if isinstance(data, dict):
                for key in ['paths', 'directories', 'results', 'data']:
                    if key in data and isinstance(data[key], list):
                        data = data[key]
                        break
            cleaned = []
            if isinstance(data, list):
                for path in data:
                    if isinstance(path, str):
                        path = path.strip()
                        if not path.startswith('/'):
                            path = '/' + path
                        path = re.sub(r'/+', '/', path)
                        if len(path) > 1 and len(path) < 200:
                            cleaned.append(path)
            print(f"[+] Parsed {len(cleaned)} valid paths")
            return list(set(cleaned))
        except Exception as e:
            print(f"[-] Parse error: {e}")
            try:
                paths = re.findall(r'["\'](/[^"\'\s]+)["\']', text)
                return list(set(paths))
            except:
                return []

class OpenAIModel(BaseAIModel):
    def __init__(self, api_key=None):
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key not found.")
        self.api_url = "https://api.openai.com/v1/chat/completions"
        self.model = "gpt-3.5-turbo"
    
    def get_model_name(self):
        return "GPT-3.5 Turbo"
    
    def generate_paths(self, context: Dict[str, Any]) -> List[str]:
        prompt = self._build_prompt(context)
        headers = {"Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"}
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You are a penetration testing expert. Generate realistic web paths for security testing. Return ONLY a JSON array of paths."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "max_tokens": 2000
        }
        try:
            response = requests.post(self.api_url, headers=headers, json=payload, timeout=60)
            if response.status_code != 200:
                raise Exception(f"OpenAI API Error: {response.status_code}")
            data = response.json()
            if 'choices' in data and len(data['choices']) > 0:
                content = data['choices'][0]['message']['content']
                return self._parse_response(content)
            else:
                raise Exception("No response from OpenAI")
        except Exception as e:
            raise Exception(f"OpenAI API error: {str(e)}")
    
    def _build_prompt(self, context: Dict[str, Any]) -> str:
        url = context.get('url', 'Unknown')
        tech = ', '.join(context.get('tech', [])[:5]) if context.get('tech') else 'Unknown'
        keywords = ', '.join(context.get('keywords', [])[:15]) if context.get('keywords') else 'None'
        return f"""Target: {url}
Technologies: {tech}
Keywords: {keywords}

Generate 60-80 paths including:
- Admin panels and dashboards
- API endpoints (REST, GraphQL)
- Config and backup files
- Technology-specific paths
- Sensitive files (.env, .git)

Return ONLY a JSON array of paths. Each path must start with /.
Example: ["/admin", "/api/v1", "/.env"]"""
    
    def _parse_response(self, text: str) -> List[str]:
        try:
            text = re.sub(r'```(json)?|```', '', text).strip()
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
            paths = re.findall(r'["\'](/[^"\'\s]+)["\']', text)
            return list(set(paths))

class LocalModel(BaseAIModel):
    def __init__(self):
        pass
    
    def get_model_name(self):
        return "Local Pattern Matcher (Enhanced)"
    
    def generate_paths(self, context: Dict[str, Any]) -> List[str]:
        paths = {
            '/admin', '/administrator', '/admin/login', '/admin/index', '/admin/dashboard', '/panel', '/control',
            '/console', '/manager', '/backend', '/backoffice', '/login', '/signin', '/auth', '/authenticate', '/session',
            '/api', '/api/v1', '/api/v2', '/api/v3', '/rest', '/restful', '/graphql', '/graphiql', '/api/docs',
            '/api/swagger', '/swagger', '/api/users', '/api/admin', '/api/auth', '/api/login',
            '/.env', '/.env.local', '/.env.production', '/.env.development', '/config', '/config.php', '/config.json',
            '/config.yml', '/settings', '/configuration', '/configure', '/.htaccess', '/.htpasswd', '/web.config',
            '/app.config', '/database.yml', '/backup', '/backups', '/backup.zip', '/backup.tar.gz', '/backup.sql',
            '/db_backup', '/dump', '/dump.sql', '/database.sql', '/old', '/oldsite', '/dev', '/development', '/test',
            '/testing', '/debug', '/temp', '/tmp', '/phpinfo.php', '/info.php', '/test.php', '/debug.php',
            '/.git', '/.git/config', '/.git/HEAD', '/.svn', '/.hg', '/logs', '/log', '/error_log', '/access_log',
            '/error.log', '/access.log', '/debug.log', '/application.log', '/robots.txt', '/sitemap.xml', '/humans.txt',
            '/security.txt', '/.well-known', '/.well-known/security.txt', '/uploads', '/files', '/media', '/images',
            '/documents', '/attachments', '/download', '/downloads', '/cgi-bin', '/scripts', '/js', '/javascript',
            '/css', '/assets'
        }
        for tech in context.get('tech', []):
            tech_lower = tech.lower()
            if 'wordpress' in tech_lower:
                paths.update(['/wp-admin', '/wp-login.php', '/wp-content', '/wp-includes', '/wp-json', '/xmlrpc.php',
                            '/wp-config.php', '/wp-config.php.bak', '/wp-content/plugins', '/wp-content/themes',
                            '/wp-content/uploads'])
            if 'php' in tech_lower:
                paths.update(['/phpinfo.php', '/info.php', '/test.php', '/shell.php', '/upload.php', '/admin.php', '/index.php'])
            if 'laravel' in tech_lower:
                paths.update(['/storage', '/storage/logs', '/.env', '/artisan', '/vendor', '/bootstrap/cache'])
            if 'django' in tech_lower or 'python' in tech_lower:
                paths.update(['/admin/', '/accounts', '/api', '/.env', '/settings.py', '/manage.py', '/requirements.txt'])
            if 'node' in tech_lower or 'express' in tech_lower:
                paths.update(['/.env', '/package.json', '/node_modules', '/dist', '/build'])
            if 'react' in tech_lower or 'vue' in tech_lower or 'angular' in tech_lower:
                paths.update(['/build', '/dist', '/public', '/src', '/.env'])
            if 'java' in tech_lower:
                paths.update(['/admin/console', '/manager', '/jmx-console', '/web-console', '/WEB-INF', '/WEB-INF/web.xml'])
            if 'asp' in tech_lower or '.net' in tech_lower:
                paths.update(['/admin', '/Admin', '/admin.aspx', '/login.aspx', '/web.config', '/Web.config'])
            if 'shopify' in tech_lower:
                paths.update(['/admin', '/cart', '/cart.json', '/checkout', '/collections', '/collections.json',
                            '/products', '/products.json', '/account', '/account/login', '/pages', '/blogs'])
        for kw in context.get('keywords', [])[:20]:
            if len(kw) > 2 and kw.isalnum():
                paths.update([f'/{kw}', f'/{kw}/admin', f'/{kw}/api', f'/{kw}.php', f'/{kw}.html'])
        return sorted(list(paths))

class AIPathGenerator:
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
        print(f"[*] Generating paths using {self.model.get_model_name()}...")
        start = time.time()
        try:
            context = {
                'url': recon_data.get('url', ''),
                'keywords': recon_data.get('keywords', [])[:25],
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