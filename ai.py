"""
Enhanced AI-powered path generation module
Multiple AI models and prompt templates
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
    """Claude AI implementation - WORKING VERSION"""
    
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
        """Generate paths using Claude AI - ACTUALLY CALLS API"""
        
        prompt = self._build_prompt(context)
        
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01"
        }
        
        payload = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "temperature": 0.7,
            "system": "You are a web security expert. Generate ONLY a JSON array of directory paths. Each path must start with /. Return only the JSON array, no explanations.",
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        }
        
        try:
            print(f"🔗 Calling Claude API...")
            response = requests.post(self.api_url, headers=headers, json=payload, timeout=60)
            
            # Check for errors
            if response.status_code == 401:
                print(f"❌ Invalid API key: {self.api_key[:15]}...")
                raise Exception("Claude API: Invalid API key")
            elif response.status_code == 402:
                print("❌ No credits available")
                print("💡 Add API credits at: https://console.anthropic.com/settings/billing")
                raise Exception("Claude API: Payment required - add API credits")
            elif response.status_code == 429:
                raise Exception("Claude API: Rate limited")
            elif response.status_code != 200:
                error_text = response.text[:200]
                raise Exception(f"Claude API Error {response.status_code}: {error_text}")
            
            data = response.json()
            
            if 'content' in data and len(data['content']) > 0:
                content = data['content'][0]['text']
                print(f"✅ Received {len(content)} chars from Claude")
                return self._parse_response(content)
            else:
                raise Exception("No content in Claude response")
            
        except requests.exceptions.RequestException as e:
            raise Exception(f"Claude API connection error: {str(e)}")
        except Exception as e:
            raise Exception(f"Claude API error: {str(e)}")
    
    def _build_prompt(self, context: Dict[str, Any]) -> str:
        """Build prompt for Claude"""
        
        url = context.get('url', 'Unknown')
        tech = ', '.join(context.get('tech', [])[:5]) if context.get('tech') else 'Unknown'
        keywords = ', '.join(context.get('keywords', [])[:15]) if context.get('keywords') else 'None'
        
        return f"""Analyze this website and generate hidden directory paths for penetration testing.

Website: {url}
Technologies: {tech}
Keywords: {keywords}

Generate 30-80 likely paths including:
- Admin panels (/admin, /login, /dashboard)
- API endpoints (/api, /api/v1, /graphql)
- Config files (/.env, /config.php, /.htaccess)
- Backups (/backup, /backup.zip, /dump.sql)
- Hidden dirs (/.git, /logs, /debug)
- Tech-specific paths based on detected technologies

Return ONLY a JSON array. Example format:
["/admin", "/api/v1", "/.env", "/wp-admin"]

Generate the JSON array now:"""
    
    def _parse_response(self, text: str) -> List[str]:
        """Parse Claude response"""
        if not text:
            return []
        
        print("📝 Parsing Claude response...")
        
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
                for key in ['paths', 'directories', 'results']:
                    if key in data and isinstance(data[key], list):
                        data = data[key]
                        break
            
            # Clean paths
            cleaned = []
            if isinstance(data, list):
                for path in data:
                    if isinstance(path, str):
                        path = path.strip()
                        if not path.startswith('/'):
                            path = '/' + path
                        if len(path) > 1 and not path.startswith('//'):
                            cleaned.append(path)
            
            print(f"✅ Parsed {len(cleaned)} valid paths")
            return list(set(cleaned))
            
        except Exception as e:
            print(f"⚠️ Parse error: {e}")
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
                {"role": "system", "content": "You are a pentesting expert. Generate ONLY a JSON array of directory paths starting with /."},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.7,
            "max_tokens": self.max_tokens,
            "response_format": {"type": "json_object"}
        }
        
        try:
            print("🔗 Calling OpenAI API...")
            response = requests.post(self.api_url, headers=headers, json=payload, timeout=60)
            
            if response.status_code != 200:
                error = response.json().get('error', {}).get('message', 'Unknown error')
                raise Exception(f"OpenAI Error: {error}")
            
            data = response.json()
            content = data['choices'][0]['message']['content']
            print(f"✅ Received response from OpenAI")
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

Return JSON with "paths" key containing 20-50 directory paths.
Example: {{"paths": ["/admin", "/api/v1", "/.env"]}}"""
    
    def _parse_response(self, text: str) -> List[str]:
        try:
            data = json.loads(text.strip())
            if isinstance(data, dict) and "paths" in data:
                paths = data["paths"]
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
            return []

class LocalModel(BaseAIModel):
    """Local pattern-based model"""
    
    def __init__(self):
        pass
    
    def get_model_name(self):
        return "Local Pattern Matcher"
    
    def generate_paths(self, context: Dict[str, Any]) -> List[str]:
        paths = {
            '/admin', '/administrator', '/login', '/signin', '/dashboard',
            '/panel', '/console', '/manager', '/api', '/api/v1', '/api/v2',
            '/graphql', '/.env', '/config.php', '/config.json', '/backup',
            '/backups', '/backup.zip', '/dump.sql', '/debug', '/test',
            '/dev', '/uploads', '/files', '/media', '/logs', '/.git',
            '/robots.txt', '/sitemap.xml', '/wp-admin', '/wp-login.php',
            '/phpinfo.php', '/info.php'
        }
        
        # Add tech-specific paths
        for tech in context.get('tech', []):
            if 'wordpress' in tech.lower():
                paths.update(['/wp-content', '/wp-includes', '/xmlrpc.php'])
            if 'php' in tech.lower():
                paths.update(['/phpinfo.php', '/test.php', '/cgi-bin/'])
        
        # Add keyword paths
        for kw in context.get('keywords', [])[:10]:
            if len(kw) > 2:
                paths.update([f'/{kw}', f'/{kw}/admin', f'/{kw}.php'])
        
        return sorted(list(paths))

class AIPathGenerator:
    """Main path generator"""
    
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
            
            print(f"✅ Using {self.model.get_model_name()}")
            
        except ValueError as e:
            print(f"⚠️ {str(e)}")
            print("🔄 Falling back to local model")
            self.model = LocalModel()
            self.model_name = "local"
    
    def generate_paths(self, recon_data, depth=1, max_paths=500):
        print(f"🔄 Generating paths using {self.model.get_model_name()}...")
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
            print(f"✅ Generated {len(paths)} paths in {duration:.2f}s")
            
            if len(paths) > max_paths:
                paths = paths[:max_paths]
            
            return sorted(list(set(paths)))
            
        except Exception as e:
            print(f"❌ Error: {e}")
            print("🔄 Using local fallback...")
            fallback = LocalModel()
            return fallback.generate_paths({'url': '', 'keywords': [], 'tech': []})