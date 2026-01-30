#!/usr/bin/env python3
"""
AIBuster Enhanced - Demo Script
Demonstrates all four major enhancements
"""
import sys
import os
import time
from colorama import Fore, Style, init

sys.path.insert(0, os.path.dirname(__file__))

from ai import EnhancedAIPathGenerator, PathLearningEngine, ContextChainer
from recon import AdvancedWebRecon
from buster import EnhancedPathBuster
from response_analyzer import ResponseAnalyzer, ContentExtractor
from adaptive_threading import AdaptiveThreadPool

init(autoreset=True)

def print_section(title):
    """Print section header"""
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"{title:^70}")
    print(f"{'='*70}{Style.RESET_ALL}\n")

def demo_enhanced_ai():
    """Demo Enhanced AI Intelligence"""
    print_section("🤖 DEMO 1: Enhanced AI Intelligence")
    
    print(f"{Fore.YELLOW}Features:{Style.RESET_ALL}")
    print("  ✓ Multi-model consensus (Claude + OpenAI + Local)")
    print("  ✓ Learning engine (improves over time)")
    print("  ✓ Context chaining (generates related paths)")
    print()
    
    recon_data = {
        'tech': ['WordPress', 'PHP', 'MySQL'],
        'keywords': ['blog', 'admin', 'posts'],
        'server': 'nginx/1.18.0',
        'title': 'My WordPress Blog'
    }
    
    print(f"{Fore.GREEN}[1] Creating AI generator with learning enabled...{Style.RESET_ALL}")
    ai_gen = EnhancedAIPathGenerator(
        model='local',
        enable_learning=True,
        enable_chaining=True
    )
    
    print(f"{Fore.GREEN}[2] Generating paths from reconnaissance data...{Style.RESET_ALL}")
    paths = ai_gen.generate_paths(recon_data, depth=2)
    print(f"   Generated: {len(paths)} paths")
    print(f"   Sample paths: {paths[:5]}")
    
    print(f"\n{Fore.GREEN}[3] Context Chaining - generating related paths...{Style.RESET_ALL}")
    discovered_paths = ['/api/v1/users', '/admin/dashboard']
    chained = ai_gen.context_chainer.chain_from_discoveries(discovered_paths)
    print(f"   From: {discovered_paths}")
    print(f"   Generated {len(chained)} related paths")
    print(f"   Examples: {list(chained)[:10]}")
    
    print(f"\n{Fore.GREEN}[4] Learning Engine - simulating learning from results...{Style.RESET_ALL}")
    mock_results = [
        {'path': '/wp-admin', 'status': 200},
        {'path': '/wp-login.php', 'status': 200},
        {'path': '/admin/config', 'status': 403},
    ]
    ai_gen.update_from_results(mock_results)
    print("   ✓ Learned from 3 results")
    print("   ✓ Patterns saved to path_learning.json")
    
    print(f"\n{Fore.YELLOW}💡 Benefits:{Style.RESET_ALL}")
    print("   • Better path quality from multiple AI models")
    print("   • Continuous improvement from scan results")
    print("   • Automatic discovery of related endpoints")

def demo_advanced_detection():
    """Demo Advanced Detection"""
    print_section("🔍 DEMO 2: Advanced Detection & Fingerprinting")
    
    print(f"{Fore.YELLOW}Features:{Style.RESET_ALL}")
    print("  ✓ WAF detection (Cloudflare, AWS, Akamai, etc.)")
    print("  ✓ CDN identification")
    print("  ✓ Technology fingerprinting with versions")
    print("  ✓ Database hints from errors")
    print("  ✓ API endpoint discovery")
    print()
    
    print(f"{Fore.GREEN}[1] Simulating advanced reconnaissance...{Style.RESET_ALL}")
    print("   (In real usage, this would scan the actual target)")
    
    mock_recon_data = {
        'url': 'https://example.com',
        'tech': ['WordPress', 'PHP', 'nginx'],
        'waf': {
            'detected': True,
            'name': 'Cloudflare',
            'confidence': 0.95,
            'indicators': ['cf-ray header', 'CF cookie']
        },
        'cdn': 'Cloudflare',
        'fingerprints': [
            {'name': 'WordPress', 'version': '6.4.2', 'confidence': 0.98},
            {'name': 'PHP', 'version': '8.1.0', 'confidence': 0.95},
            {'name': 'nginx', 'version': '1.18.0', 'confidence': 0.90}
        ],
        'version_info': {
            'WordPress': '6.4.2',
            'PHP': '8.1.0',
            'nginx': '1.18.0'
        },
        'api_endpoints': [
            '/api/v1/posts',
            '/wp-json/wp/v2/users',
            '/graphql'
        ],
        'security_headers': {
            'present': ['X-Frame-Options', 'X-Content-Type-Options'],
            'missing': ['Strict-Transport-Security', 'Content-Security-Policy']
        }
    }
    
    print(f"\n{Fore.GREEN}[2] WAF Detection:{Style.RESET_ALL}")
    if mock_recon_data['waf']['detected']:
        print(f"   ⚠️  {Fore.RED}WAF Detected: {mock_recon_data['waf']['name']}{Style.RESET_ALL}")
        print(f"   Confidence: {mock_recon_data['waf']['confidence']:.0%}")
        print(f"   Indicators: {', '.join(mock_recon_data['waf']['indicators'])}")
    
    print(f"\n{Fore.GREEN}[3] Technology Fingerprints:{Style.RESET_ALL}")
    for fp in mock_recon_data['fingerprints']:
        print(f"   ✓ {fp['name']} {fp['version']} (confidence: {fp['confidence']:.0%})")
    
    print(f"\n{Fore.GREEN}[4] API Endpoints Discovered:{Style.RESET_ALL}")
    for endpoint in mock_recon_data['api_endpoints']:
        print(f"   🔌 {endpoint}")
    
    print(f"\n{Fore.GREEN}[5] Security Headers Analysis:{Style.RESET_ALL}")
    print(f"   Present: {', '.join(mock_recon_data['security_headers']['present'])}")
    print(f"   {Fore.YELLOW}Missing: {', '.join(mock_recon_data['security_headers']['missing'])}{Style.RESET_ALL}")
    
    print(f"\n{Fore.YELLOW}💡 Benefits:{Style.RESET_ALL}")
    print("   • Know what security measures are in place")
    print("   • Version-specific vulnerability assessment")
    print("   • Better path generation from detailed fingerprints")

def demo_response_analysis():
    """Demo Response Analysis"""
    print_section("📊 DEMO 3: Intelligent Response Analysis")
    
    print(f"{Fore.YELLOW}Features:{Style.RESET_ALL}")
    print("  ✓ Soft-404 detection")
    print("  ✓ Wildcard response filtering")
    print("  ✓ Login/Admin page classification")
    print("  ✓ Secret extraction")
    print("  ✓ Content similarity grouping")
    print()
    
    analyzer = ResponseAnalyzer()
    extractor = ContentExtractor()
    
    print(f"{Fore.GREEN}[1] Analyzing mock responses...{Style.RESET_ALL}")
    
    mock_responses = [
        {
            'path': '/admin',
            'status': 200,
            'content': b'<html><head><title>Admin Login</title></head><body><form action="/login"><input type="text" name="username"><input type="password" name="password"></form></body></html>',
            'headers': {'Content-Type': 'text/html'},
            'time': 0.5
        },
        {
            'path': '/api/users',
            'status': 200,
            'content': b'{"users": [{"id": 1, "name": "John"}], "api_key": "sk_test_1234567890abcdef"}',
            'headers': {'Content-Type': 'application/json'},
            'time': 0.3
        },
        {
            'path': '/random123',
            'status': 200,
            'content': b'<html><head><title>404 Not Found</title></head><body>Page not found</body></html>',
            'headers': {'Content-Type': 'text/html'},
            'time': 0.2
        }
    ]
    
    for i, resp in enumerate(mock_responses, 1):
        analysis, classification = analyzer.analyze_response(
            resp['path'],
            resp['status'],
            resp['content'],
            resp['headers'],
            resp['time']
        )
        
        print(f"\n   Response {i}: {resp['path']}")
        
        if classification.is_login_page:
            print(f"      {Fore.CYAN}→ Login page detected!{Style.RESET_ALL}")
        
        if classification.is_api_endpoint:
            print(f"      {Fore.CYAN}→ API endpoint detected!{Style.RESET_ALL}")
            
            secrets = extractor.extract_secrets(resp['content'].decode())
            if secrets:
                print(f"      {Fore.RED}⚠️  Secrets found:{Style.RESET_ALL}")
                for secret in secrets:
                    print(f"         - {secret['type']}: {secret['value'][:50]}")
        
        if classification.is_soft_404:
            print(f"      {Fore.YELLOW}→ Soft 404 detected (looks like error page){Style.RESET_ALL}")
    
    print(f"\n{Fore.GREEN}[2] Response Grouping:{Style.RESET_ALL}")
    similar = analyzer.get_similar_responses(min_count=1)
    print(f"   Found {len(similar)} unique response signatures")
    
    print(f"\n{Fore.YELLOW}💡 Benefits:{Style.RESET_ALL}")
    print("   • Filters out false positives (soft 404s)")
    print("   • Identifies high-value targets (login, admin)")
    print("   • Extracts secrets from responses")
    print("   • Groups similar responses to find wildcards")

def demo_adaptive_threading():
    """Demo Adaptive Threading"""
    print_section("⚡ DEMO 4: Adaptive Threading & Performance")
    
    print(f"{Fore.YELLOW}Features:{Style.RESET_ALL}")
    print("  ✓ Auto-adjusts thread count")
    print("  ✓ Responds to rate limiting")
    print("  ✓ Optimizes based on response times")
    print("  ✓ Smart connection pooling")
    print()
    
    print(f"{Fore.GREEN}[1] Creating adaptive thread pool...{Style.RESET_ALL}")
    pool = AdaptiveThreadPool(
        initial_threads=10,
        min_threads=5,
        max_threads=20,
        auto_adjust=True
    )
    print(f"   Initial threads: {pool.current_threads}")
    print(f"   Range: {pool.min_threads} - {pool.max_threads}")
    
    print(f"\n{Fore.GREEN}[2] Simulating scan with performance variations...{Style.RESET_ALL}")
    
    scenarios = [
        ("Fast responses, low errors", [(0.2, True)] * 10, "increase"),
        ("Slow responses", [(3.0, True)] * 10, "decrease"),
        ("High error rate", [(0.5, False)] * 10, "decrease"),
        ("Rate limiting", [(0.5, False, 'rate_limit')] * 5, "decrease"),
    ]
    
    for scenario_name, requests, expected in scenarios:
        print(f"\n   Scenario: {Fore.CYAN}{scenario_name}{Style.RESET_ALL}")
        
        old_threads = pool.current_threads
        
        for req_data in requests:
            if len(req_data) == 3:
                response_time, success, error_type = req_data
            else:
                response_time, success = req_data
                error_type = None
            
            pool.record_request(response_time, success, error_type)
        
        new_threads = pool.current_threads
        
        if old_threads != new_threads:
            arrow = "↑" if new_threads > old_threads else "↓"
            color = Fore.GREEN if new_threads > old_threads else Fore.YELLOW
            print(f"      {color}Threads: {old_threads} {arrow} {new_threads}{Style.RESET_ALL}")
        else:
            print(f"      Threads: {old_threads} (stable)")
    
    print(f"\n{Fore.GREEN}[3] Final Statistics:{Style.RESET_ALL}")
    stats = pool.get_statistics()
    print(f"   Current threads: {stats['current_threads']}")
    print(f"   Total requests: {stats['total_requests']}")
    print(f"   Success rate: {stats['success_rate']:.1%}")
    print(f"   Avg response: {stats['avg_response_time']:.2f}s")
    print(f"   Timeouts: {stats['timeouts']}")
    print(f"   Rate limits: {stats['rate_limit_hits']}")
    
    print(f"\n{Fore.YELLOW}💡 Benefits:{Style.RESET_ALL}")
    print("   • Automatically optimizes for best performance")
    print("   • Prevents overwhelming the target")
    print("   • Adapts to changing network conditions")
    print("   • Reduces manual tuning needed")

def demo_full_integration():
    """Demo Full Integration"""
    print_section("🎯 DEMO 5: Full Integration Example")
    
    print(f"{Fore.YELLOW}This shows how all components work together:{Style.RESET_ALL}\n")
    
    print(f"{Fore.GREEN}[1] Advanced Reconnaissance{Style.RESET_ALL}")
    print("   → Detects WAF, CDN, technologies, versions")
    print("   → Discovers API endpoints and security headers")
    
    print(f"\n{Fore.GREEN}[2] Enhanced AI Path Generation{Style.RESET_ALL}")
    print("   → Uses reconnaissance data for context")
    print("   → Multi-model consensus for best paths")
    print("   → Learns from previous scans")
    
    print(f"\n{Fore.GREEN}[3] Adaptive Scanning{Style.RESET_ALL}")
    print("   → Starts with configured thread count")
    print("   → Adjusts based on server performance")
    print("   → Backs off on rate limiting")
    
    print(f"\n{Fore.GREEN}[4] Intelligent Analysis{Style.RESET_ALL}")
    print("   → Filters soft-404s and wildcards")
    print("   → Classifies login/admin/API pages")
    print("   → Extracts secrets and forms")
    
    print(f"\n{Fore.GREEN}[5] Continuous Learning{Style.RESET_ALL}")
    print("   → Updates learning data from results")
    print("   → Generates related paths from discoveries")
    print("   → Improves future scans")
    
    print(f"\n{Fore.CYAN}Code Example:{Style.RESET_ALL}")
    print(f'''
    # Complete scan with all enhancements
    recon = AdvancedWebRecon(url)
    recon_data = recon.analyze()
    
    ai_gen = EnhancedAIPathGenerator(enable_learning=True)
    paths = ai_gen.generate_paths(recon_data, use_consensus=True)
    
    buster = EnhancedPathBuster(url, adaptive_threads=True)
    results = buster.bust(paths)
    
    # Learn from results
    ai_gen.update_from_results(results['results']['found'])
    
    # Generate more paths from discoveries
    more_paths = ai_gen.generate_paths(
        recon_data,
        discovered_paths=[r['path'] for r in results['results']['found']]
    )
    ''')

def main():
    """Run all demos"""
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"{'AIBuster Enhanced - Feature Demonstrations':^70}")
    print(f"{'='*70}{Style.RESET_ALL}\n")
    
    print(f"{Fore.YELLOW}This demo showcases the four major enhancements:{Style.RESET_ALL}")
    print("  1. Enhanced AI Intelligence")
    print("  2. Advanced Detection & Fingerprinting")
    print("  3. Intelligent Response Analysis")
    print("  4. Adaptive Threading & Performance")
    print("  5. Full Integration")
    
    input(f"\n{Fore.GREEN}Press Enter to start demos...{Style.RESET_ALL}")
    
    try:
        demo_enhanced_ai()
        input(f"\n{Fore.GREEN}Press Enter for next demo...{Style.RESET_ALL}")
        
        demo_advanced_detection()
        input(f"\n{Fore.GREEN}Press Enter for next demo...{Style.RESET_ALL}")
        
        demo_response_analysis()
        input(f"\n{Fore.GREEN}Press Enter for next demo...{Style.RESET_ALL}")
        
        demo_adaptive_threading()
        input(f"\n{Fore.GREEN}Press Enter for final demo...{Style.RESET_ALL}")
        
        demo_full_integration()
        
        print_section("✅ All Demos Complete!")
        
        print(f"{Fore.CYAN}Next Steps:{Style.RESET_ALL}")
        print("  1. Review INTEGRATION_GUIDE.md for integration steps")
        print("  2. Copy enhanced modules to your AIBuster directory")
        print("  3. Update your main script imports")
        print("  4. Test with a safe target")
        print("  5. Monitor the performance improvements")
        
        print(f"\n{Fore.GREEN}Thank you for trying AIBuster Enhanced!{Style.RESET_ALL}\n")
        
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Demo interrupted. Goodbye!{Style.RESET_ALL}\n")
        sys.exit(0)

if __name__ == "__main__":
    main()