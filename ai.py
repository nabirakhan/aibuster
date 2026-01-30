#!/usr/bin/env python3
import os
import json
import re
from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import logging

@dataclass
class PathContext:
    """Context information for intelligent path generation"""
    discovered_paths: List[str] = field(default_factory=list)
    successful_patterns: Dict[str, int] = field(default_factory=dict)
    technology_stack: List[str] = field(default_factory=list)
    version_info: Dict[str, str] = field(default_factory=dict)
    api_patterns: List[str] = field(default_factory=list)
    keywords: List[str] = field(default_factory=list)

@dataclass
class ModelResult:
    """Result from a single AI model"""
    model_name: str
    paths: List[str]
    confidence: float
    generation_time: float

class PathLearningEngine:
    """Learns from scan results to improve future path generation"""
    
    def __init__(self, learning_file: str = "path_learning.json"):
        self.learning_file = learning_file
        self.success_patterns = defaultdict(int)
        self.failure_patterns = defaultdict(int)
        self.tech_specific_patterns = defaultdict(lambda: defaultdict(int))
        self.logger = logging.getLogger(__name__)
        self.load_learning_data()
    
    def load_learning_data(self):
        """Load previously learned patterns"""
        if os.path.exists(self.learning_file):
            try:
                with open(self.learning_file, 'r') as f:
                    data = json.load(f)
                    self.success_patterns = defaultdict(int, data.get('success', {}))
                    self.failure_patterns = defaultdict(int, data.get('failure', {}))
                    self.tech_specific_patterns = defaultdict(
                        lambda: defaultdict(int), 
                        {k: defaultdict(int, v) for k, v in data.get('tech_patterns', {}).items()}
                    )
                self.logger.info(f"Loaded {len(self.success_patterns)} success patterns")
            except Exception as e:
                self.logger.warning(f"Could not load learning data: {e}")
    
    def save_learning_data(self):
        """Save learned patterns for future use"""
        try:
            data = {
                'success': dict(self.success_patterns),
                'failure': dict(self.failure_patterns),
                'tech_patterns': {k: dict(v) for k, v in self.tech_specific_patterns.items()}
            }
            with open(self.learning_file, 'w') as f:
                json.dump(data, f, indent=2)
            self.logger.info("Saved learning data")
        except Exception as e:
            self.logger.error(f"Could not save learning data: {e}")
    
    def learn_from_results(self, results: List[Dict], technologies: List[str]):
        """Learn from scan results"""
        for result in results:
            path = result.get('path', '')
            status = result.get('status', 0)
            
            pattern = self._extract_pattern(path)
            
            if status == 200:
                self.success_patterns[pattern] += 1
                for tech in technologies:
                    self.tech_specific_patterns[tech][pattern] += 1
            elif status in [404, 403]:
                self.failure_patterns[pattern] += 1
        
        self.save_learning_data()
    
    def _extract_pattern(self, path: str) -> str:
        """Extract a generalizable pattern from a path"""
        path = re.sub(r'/\d+/', '/[ID]/', path)
        path = re.sub(r'\d{4}-\d{2}-\d{2}', '[DATE]', path)
        path = re.sub(r'[a-f0-9]{32,}', '[HASH]', path)
        path = re.sub(r'v\d+', 'v[N]', path)
        return path
    
    def get_high_value_patterns(self, technologies: List[str], limit: int = 20) -> List[str]:
        """Get patterns likely to succeed based on learning"""
        patterns = []
        
        for tech in technologies:
            tech_patterns = self.tech_specific_patterns.get(tech, {})
            sorted_patterns = sorted(tech_patterns.items(), key=lambda x: x[1], reverse=True)
            patterns.extend([p[0] for p in sorted_patterns[:limit]])
        
        general_patterns = sorted(self.success_patterns.items(), key=lambda x: x[1], reverse=True)
        patterns.extend([p[0] for p in general_patterns[:limit]])
        
        return list(set(patterns))

class ContextChainer:
    """Generates related paths based on discovered paths"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.api_version_pattern = re.compile(r'/api/v(\d+)/')
        self.resource_pattern = re.compile(r'/([a-z_]+)/?$')
        self.id_pattern = re.compile(r'/(\d+)/?$')
    
    def chain_from_discoveries(self, discovered_paths: List[str]) -> List[str]:
        """Generate related paths from discoveries"""
        chained_paths = set()
        
        for path in discovered_paths:
            chained_paths.update(self._chain_api_versions(path))
            chained_paths.update(self._chain_resources(path))
            chained_paths.update(self._chain_crud_operations(path))
            chained_paths.update(self._chain_common_siblings(path))
            chained_paths.update(self._chain_depth_variations(path))
        
        return list(chained_paths)
    
    def _chain_api_versions(self, path: str) -> Set[str]:
        """Generate other API versions"""
        paths = set()
        match = self.api_version_pattern.search(path)
        if match:
            current_version = int(match.group(1))
            base_path = path[:match.start()]
            end_path = path[match.end()-1:]
            
            for v in range(1, max(current_version + 3, 5)):
                if v != current_version:
                    paths.add(f"{base_path}/api/v{v}{end_path}")
        return paths
    
    def _chain_resources(self, path: str) -> Set[str]:
        """Generate common resource variations"""
        paths = set()
        common_resources = {
            'user': ['users', 'accounts', 'profiles', 'members'],
            'product': ['products', 'items', 'goods', 'catalog'],
            'order': ['orders', 'purchases', 'transactions'],
            'post': ['posts', 'articles', 'content', 'blogs'],
            'comment': ['comments', 'reviews', 'feedback'],
            'file': ['files', 'documents', 'uploads', 'media'],
            'admin': ['admin', 'administrator', 'management', 'dashboard'],
            'api': ['api', 'rest', 'graphql', 'v1', 'v2']
        }
        
        for singular, variations in common_resources.items():
            if singular in path.lower():
                for variation in variations:
                    paths.add(path.replace(singular, variation))
                    paths.add(path.replace(singular.capitalize(), variation.capitalize()))
        
        return paths
    
    def _chain_crud_operations(self, path: str) -> Set[str]:
        """Generate CRUD operation variations"""
        paths = set()
        operations = ['create', 'read', 'update', 'delete', 'list', 'get', 'post', 'put', 'patch']
        
        for op in operations:
            if path.endswith('/'):
                paths.add(f"{path}{op}")
            else:
                paths.add(f"{path}/{op}")
        
        return paths
    
    def _chain_common_siblings(self, path: str) -> Set[str]:
        """Generate common sibling paths"""
        paths = set()
        parts = path.rstrip('/').split('/')
        
        if len(parts) > 1:
            base = '/'.join(parts[:-1])
            siblings = ['config', 'settings', 'info', 'status', 'health', 'debug', 
                       'test', 'admin', 'docs', 'swagger', 'schema', 'metadata']
            
            for sibling in siblings:
                paths.add(f"{base}/{sibling}")
        
        return paths
    
    def _chain_depth_variations(self, path: str) -> Set[str]:
        """Generate depth variations of discovered paths"""
        paths = set()
        parts = path.rstrip('/').split('/')
        
        for i in range(1, len(parts)):
            partial = '/'.join(parts[:i+1])
            paths.add(partial)
            paths.add(f"{partial}/")
        
        return paths

class EnhancedAIPathGenerator:
    """Enhanced AI path generator with multi-model consensus and learning"""
    
    def __init__(self, model: str = "local", api_key: Optional[str] = None, 
                 enable_learning: bool = True, enable_chaining: bool = True):
        self.model = model
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY') or os.getenv('OPENAI_API_KEY')
        self.logger = logging.getLogger(__name__)
        self.enable_learning = enable_learning
        self.enable_chaining = enable_chaining
        
        if enable_learning:
            self.learning_engine = PathLearningEngine()
        
        if enable_chaining:
            self.context_chainer = ContextChainer()
        
        self.context = PathContext()
        
        if model == "claude" and self.api_key:
            try:
                from anthropic import Anthropic
                self.claude_client = Anthropic(api_key=self.api_key)
            except ImportError:
                self.logger.warning("Anthropic library not installed. Install with: pip install anthropic")
                self.model = "local"
        
        if model == "openai" and self.api_key:
            try:
                from openai import OpenAI
                self.openai_client = OpenAI(api_key=self.api_key)
            except ImportError:
                self.logger.warning("OpenAI library not installed. Install with: pip install openai")
                self.model = "local"
    
    def generate_paths(self, recon_data: Dict, depth: int = 1, 
                      discovered_paths: Optional[List[str]] = None,
                      use_consensus: bool = False) -> List[str]:
        """Generate intelligent paths with optional multi-model consensus"""
        
        self.context.technology_stack = recon_data.get('tech', [])
        self.context.keywords = recon_data.get('keywords', [])
        self.context.discovered_paths = discovered_paths or []
        
        all_paths = set()
        
        if use_consensus and self.api_key:
            paths = self._multi_model_consensus(recon_data, depth)
        else:
            if self.model == "claude":
                paths = self._generate_claude_paths(recon_data, depth)
            elif self.model == "openai":
                paths = self._generate_openai_paths(recon_data, depth)
            else:
                paths = self._generate_local_paths(recon_data, depth)
        
        all_paths.update(paths)
        
        if self.enable_learning:
            learned_patterns = self.learning_engine.get_high_value_patterns(
                self.context.technology_stack, limit=30
            )
            all_paths.update(learned_patterns)
            self.logger.info(f"Added {len(learned_patterns)} learned patterns")
        
        if self.enable_chaining and discovered_paths:
            chained_paths = self.context_chainer.chain_from_discoveries(discovered_paths)
            all_paths.update(chained_paths)
            self.logger.info(f"Added {len(chained_paths)} chained paths from discoveries")
        
        return sorted(list(all_paths))
    
    def _multi_model_consensus(self, recon_data: Dict, depth: int) -> List[str]:
        """Use multiple models and combine results with weighted consensus"""
        import time
        
        results = []
        
        models_to_try = []
        if hasattr(self, 'claude_client'):
            models_to_try.append('claude')
        if hasattr(self, 'openai_client'):
            models_to_try.append('openai')
        models_to_try.append('local')
        
        for model in models_to_try[:2]:
            try:
                start_time = time.time()
                
                if model == 'claude':
                    paths = self._generate_claude_paths(recon_data, depth)
                    confidence = 0.9
                elif model == 'openai':
                    paths = self._generate_openai_paths(recon_data, depth)
                    confidence = 0.85
                else:
                    paths = self._generate_local_paths(recon_data, depth)
                    confidence = 0.7
                
                elapsed = time.time() - start_time
                
                results.append(ModelResult(
                    model_name=model,
                    paths=paths,
                    confidence=confidence,
                    generation_time=elapsed
                ))
                
                self.logger.info(f"{model} generated {len(paths)} paths in {elapsed:.2f}s")
                
            except Exception as e:
                self.logger.error(f"Error with {model}: {e}")
        
        consensus_paths = self._combine_model_results(results)
        self.logger.info(f"Consensus generated {len(consensus_paths)} unique paths")
        
        return consensus_paths
    
    def _combine_model_results(self, results: List[ModelResult]) -> List[str]:
        """Combine results from multiple models with weighted voting"""
        path_votes = defaultdict(float)
        
        for result in results:
            for path in result.paths:
                path_votes[path] += result.confidence
        
        threshold = max(path_votes.values()) * 0.3 if path_votes else 0
        
        consensus_paths = [path for path, score in path_votes.items() if score >= threshold]
        
        return consensus_paths
    
    def _generate_claude_paths(self, recon_data: Dict, depth: int) -> List[str]:
        """Generate paths using Claude with enhanced prompts"""
        if not hasattr(self, 'claude_client'):
            return self._generate_local_paths(recon_data, depth)
        
        tech = recon_data.get('tech', [])
        keywords = recon_data.get('keywords', [])
        server = recon_data.get('server', '')
        title = recon_data.get('title', '')
        
        discovered_context = ""
        if self.context.discovered_paths:
            discovered_context = f"\n\nPreviously discovered paths:\n" + "\n".join(self.context.discovered_paths[:20])
        
        prompt = f"""You are an expert penetration tester specializing in web application enumeration.

Target Information:
- Technologies detected: {', '.join(tech) if tech else 'Unknown'}
- Server: {server}
- Page title: {title}
- Keywords found: {', '.join(keywords[:10]) if keywords else 'None'}
{discovered_context}

Generate a comprehensive list of 80-120 high-probability directory and file paths for this target.

CRITICAL REQUIREMENTS:
1. Generate ONLY the paths, one per line
2. Each path must start with /
3. NO explanations, categories, or markdown
4. Focus on paths specific to detected technologies
5. Include version-specific paths when technology versions are known
6. Include both common and uncommon paths
7. Consider security testing paths (admin panels, configs, backups, APIs)
8. If previous paths are provided, generate related/similar paths

Categories to cover (but don't label them in output):
- Admin interfaces & dashboards
- API endpoints (REST, GraphQL, SOAP)
- Configuration files & environment files  
- Backup files & archives
- Development/testing endpoints
- Database interfaces
- File upload locations
- Authentication endpoints
- Technology-specific paths
- Version control artifacts

Return ONLY paths, nothing else:"""

        try:
            message = self.claude_client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4000,
                temperature=0.7,
                messages=[{"role": "user", "content": prompt}]
            )
            
            response_text = message.content[0].text
            paths = [line.strip() for line in response_text.split('\n') 
                    if line.strip() and line.strip().startswith('/')]
            
            return paths
            
        except Exception as e:
            self.logger.error(f"Claude generation error: {e}")
            return self._generate_local_paths(recon_data, depth)
    
    def _generate_openai_paths(self, recon_data: Dict, depth: int) -> List[str]:
        """Generate paths using OpenAI GPT"""
        if not hasattr(self, 'openai_client'):
            return self._generate_local_paths(recon_data, depth)
        
        tech = recon_data.get('tech', [])
        keywords = recon_data.get('keywords', [])
        
        discovered_context = ""
        if self.context.discovered_paths:
            discovered_context = f"\n\nPreviously discovered:\n" + "\n".join(self.context.discovered_paths[:20])
        
        prompt = f"""Generate 60-80 high-probability web paths for penetration testing.

Target details:
- Technologies: {', '.join(tech)}
- Keywords: {', '.join(keywords[:10])}
{discovered_context}

Requirements:
- Only output paths, one per line
- Each path starts with /
- No explanations or categories
- Include admin, API, config, backup, dev paths
- Focus on detected technologies
- Include version-specific paths

Output only the paths:"""

        try:
            response = self.openai_client.chat.completions.create(
                model="gpt-4-turbo-preview",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2000,
                temperature=0.7
            )
            
            response_text = response.choices[0].message.content
            paths = [line.strip() for line in response_text.split('\n') 
                    if line.strip() and line.strip().startswith('/')]
            
            return paths
            
        except Exception as e:
            self.logger.error(f"OpenAI generation error: {e}")
            return self._generate_local_paths(recon_data, depth)
    
    def _generate_local_paths(self, recon_data: Dict, depth: int) -> List[str]:
        """Enhanced local path generation with pattern-based intelligence"""
        paths = set()
        tech = recon_data.get('tech', [])
        keywords = recon_data.get('keywords', [])
        
        base_paths = {
            '/admin', '/administrator', '/admin-console', '/admin-panel', '/admin.php',
            '/login', '/signin', '/auth', '/authenticate', '/login.php',
            '/dashboard', '/panel', '/console', '/manager', '/control',
            '/api', '/api/v1', '/api/v2', '/api/v3', '/rest', '/graphql', '/graphiql',
            '/config', '/configuration', '/settings', '/setup', '/install',
            '/.env', '/.env.local', '/.env.production', '/config.php', '/config.json',
            '/backup', '/backups', '/backup.zip', '/backup.tar.gz', '/db_backup',
            '/.git', '/.git/config', '/.svn', '/CVS',
            '/test', '/testing', '/dev', '/development', '/debug', '/temp',
            '/uploads', '/upload', '/files', '/media', '/assets', '/static',
            '/logs', '/log', '/error_log', '/access_log', '/debug.log',
            '/docs', '/documentation', '/swagger', '/api-docs', '/openapi.json',
            '/robots.txt', '/sitemap.xml', '/humans.txt', '/security.txt',
            '/.well-known', '/.well-known/security.txt', '/.well-known/change-password'
        }
        paths.update(base_paths)
        
        if 'WordPress' in tech:
            paths.update({
                '/wp-admin', '/wp-login.php', '/wp-content', '/wp-includes',
                '/wp-json', '/wp-json/wp/v2/users', '/xmlrpc.php',
                '/wp-config.php', '/wp-config.php.bak', '/license.txt',
                '/readme.html', '/wp-content/uploads', '/wp-content/plugins',
                '/wp-content/themes', '/wp-admin/install.php'
            })
        
        if 'Joomla' in tech:
            paths.update({
                '/administrator', '/administrator/index.php', '/configuration.php',
                '/components', '/modules', '/plugins', '/templates',
                '/libraries', '/cache', '/logs', '/tmp'
            })
        
        if 'Drupal' in tech:
            paths.update({
                '/user/login', '/admin/config', '/sites/default/settings.php',
                '/CHANGELOG.txt', '/core', '/modules', '/themes',
                '/sites/default/files'
            })
        
        if 'Laravel' in tech:
            paths.update({
                '/storage', '/storage/logs', '/.env', '/.env.example',
                '/artisan', '/public/storage', '/bootstrap/cache',
                '/config', '/routes', '/database'
            })
        
        if 'Django' in tech:
            paths.update({
                '/admin', '/admin/login', '/static', '/media',
                '/settings.py', '/manage.py', '/__debug__',
                '/api/schema', '/api/docs'
            })
        
        if 'ASP.NET' in tech or 'IIS' in tech:
            paths.update({
                '/web.config', '/Web.config', '/bin', '/App_Data',
                '/App_Code', '/aspnet_client', '/trace.axd',
                '/elmah.axd', '/glimpse.axd'
            })
        
        if 'PHP' in tech:
            paths.update({
                '/phpinfo.php', '/info.php', '/test.php', '/php.ini',
                '/composer.json', '/composer.lock', '/vendor'
            })
        
        if 'Node.js' in tech or 'Express' in tech:
            paths.update({
                '/package.json', '/package-lock.json', '/node_modules',
                '/.env', '/dist', '/build', '/server.js'
            })
        
        if 'Shopify' in tech:
            paths.update({
                '/admin', '/cart', '/checkout', '/account', '/collections',
                '/products', '/pages', '/policies', '/search'
            })
        
        api_paths = {
            '/api/users', '/api/products', '/api/orders', '/api/auth',
            '/api/login', '/api/register', '/api/config', '/api/status',
            '/api/health', '/api/version', '/api/swagger.json',
            '/v1/users', '/v2/users', '/v1/products', '/v2/products'
        }
        paths.update(api_paths)
        
        for keyword in keywords[:15]:
            if len(keyword) > 3:
                paths.add(f"/{keyword.lower()}")
                paths.add(f"/{keyword.lower()}s")
                paths.add(f"/api/{keyword.lower()}")
        
        return list(paths)
    
    def update_from_results(self, results: List[Dict]):
        """Update learning engine from scan results"""
        if self.enable_learning:
            self.learning_engine.learn_from_results(results, self.context.technology_stack)