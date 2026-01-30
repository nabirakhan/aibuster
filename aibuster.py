#!/usr/bin/env python3
import argparse
import sys
import signal
import os
from colorama import Fore, Style, init
from ai import EnhancedAIPathGenerator
from recon import AdvancedWebRecon
from buster import EnhancedPathBuster
from output import OutputFormatter
try:
    from plugins import PluginManager
    PLUGINS_AVAILABLE = True
except ImportError:
    PLUGINS_AVAILABLE = False
import logging

init(autoreset=True)
VERSION = "2.5.0"

def signal_handler(sig, frame):
    print(f"\n{Fore.YELLOW}[!] Scan interrupted by user{Style.RESET_ALL}")
    sys.exit(0)

def banner():
    lines = [
        "    █████╗ ██╗██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗ ",
        "   ██╔══██╗██║██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗",
        "   ███████║██║██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝",
        "   ██╔══██║██║██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗",
        "   ██║  ██║██║██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║",
        "   ╚═╝  ╚═╝╚═╝╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝"
    ]
    colors = [Fore.CYAN, Fore.BLUE, Fore.MAGENTA, Fore.RED, Fore.MAGENTA, Fore.BLUE]
    box_width = 81
    top_border = "═" * (box_width - 2)
    bottom_border = "═" * (box_width - 2)
    
    print(f"{Fore.CYAN}╔{top_border}╗")
    print(f"{Fore.CYAN}║{' ' * (box_width - 2)}║")
    
    for i, line in enumerate(lines):
        color = colors[i % len(colors)]
        line_len = len(line)
        left_padding = (box_width - 2 - line_len) // 2
        right_padding = box_width - 2 - line_len - left_padding
        
        print(f"{Fore.CYAN}║{' ' * left_padding}{color}{line}{' ' * right_padding}{Fore.CYAN}║")
    
    print(f"{Fore.CYAN}║{' ' * (box_width - 2)}║")
    title1 = "AI-Powered Intelligent Directory Enumeration Tool"
    title2 = "Advanced Recon • Neural Analysis • Context-Aware"
    
    title1_left = (box_width - 2 - len(title1)) // 2
    title1_right = box_width - 2 - len(title1) - title1_left
    
    title2_left = (box_width - 2 - len(title2)) // 2
    title2_right = box_width - 2 - len(title2) - title2_left
    
    print(f"{Fore.CYAN}║{' ' * title1_left}{title1}{' ' * title1_right}{Fore.CYAN}║")
    print(f"{Fore.CYAN}║{' ' * title2_left}{title2}{' ' * title2_right}{Fore.CYAN}║")
    
    print(f"{Fore.CYAN}║{' ' * (box_width - 2)}║")
    print(f"{Fore.CYAN}╚{bottom_border}╝")
    status_border = "═" * (box_width - 2)
    
    print(f"""
{Fore.WHITE}{status_border}
                         » SYSTEM STATUS «                                
{status_border}

{Fore.YELLOW}  VERSION:{Style.RESET_ALL}        v{VERSION}
{Fore.YELLOW}  NEURAL ENGINE:{Style.RESET_ALL} SPECTER (AUTOMATED)
{Fore.YELLOW}  SCAN MODE:{Style.RESET_ALL}     ACTIVE RECONNAISSANCE
{Fore.YELLOW}  AUTHOR:{Style.RESET_ALL}        Nabira Khan

{Fore.WHITE}{status_border}{Style.RESET_ALL}
""")

def parse_args():
    parser = argparse.ArgumentParser(
        description="AIBuster - AI-powered directory enumeration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s -u https://example.com
  %(prog)s -u https://target.com -t 20 -v -o results.json
  %(prog)s -u https://target.com --ai-model claude --format html
  %(prog)s -u https://target.com --plugins wordpress,sensitive-files,api-scanner,shopify"""
    )
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=5, help="Request timeout in seconds (default: 5)")
    parser.add_argument("--delay", type=float, default=0, help="Delay between requests in seconds")
    parser.add_argument("--retries", type=int, default=2, help="Number of retries for failed requests")
    parser.add_argument("--no-ai", action="store_true", help="Disable AI path generation")
    parser.add_argument("--ai-model", default="local", choices=["claude", "openai", "local"], help="AI model to use (default: local)")
    parser.add_argument("--api-key", help="API key for AI services (Claude/OpenAI)")
    parser.add_argument("--wordlist", help="Use custom wordlist instead of AI")
    parser.add_argument("--extensions", default="php,html,js,txt,json", help="File extensions to test (comma-separated)")
    parser.add_argument("--depth", type=int, default=1, help="Directory depth to scan (1-3)")
    parser.add_argument("-o", "--output", help="Save results to file")
    parser.add_argument("--format", default="json", choices=["json", "csv", "html", "xml", "md"], help="Output format (default: json)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--debug", action="store_true", help="Debug mode with detailed logging")
    parser.add_argument("--quiet", action="store_true", help="Minimal output (only results)")
    parser.add_argument("--plugins", help="Enable plugins (comma-separated: wordpress,api-scanner,sensitive-files,shopify)")
    parser.add_argument("--proxy", help="Use proxy (format: http://proxy:port)")
    parser.add_argument("--rate-limit", type=int, help="Maximum requests per minute")
    parser.add_argument("--cookies", help="Cookies to send with requests")
    parser.add_argument("--headers", help="Custom headers (JSON string)")
    parser.add_argument("--user-agent", default="Mozilla/5.0 (AIBuster-Scanner)", help="Custom User-Agent string")
    return parser.parse_args()

def setup_logging(args):
    level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[logging.FileHandler('aibuster.log'), logging.StreamHandler() if not args.quiet else logging.NullHandler()]
    )
    return logging.getLogger(__name__)

def validate_args(args):
    if not args.url.startswith(('http://', 'https://')):
        raise ValueError("URL must start with http:// or https://")
    if args.threads < 1 or args.threads > 100:
        raise ValueError("Threads must be between 1 and 100")
    if args.depth < 1 or args.depth > 3:
        raise ValueError("Depth must be between 1 and 3")
    if not args.no_ai and args.ai_model in ['claude', 'openai']:
        if not args.api_key and not os.getenv('ANTHROPIC_API_KEY') and not os.getenv('OPENAI_API_KEY'):
            print(f"{Fore.YELLOW}[!] Warning: No API key provided for {args.ai_model}. Falling back to local mode.{Style.RESET_ALL}")
            args.ai_model = 'local'
    return True

def get_builtin_paths(recon_data):
    paths = ['/admin', '/administrator', '/login', '/dashboard', '/api', '/api/v1', '/api/v2', '/graphql', '/graphiql',
             '/config', '/configuration', '/settings', '/.env', '/config.php', '/config.json', '/.git', '/git', '/svn', '/.svn',
             '/backup', '/backups', '/backup.zip', '/backup.tar', '/db', '/database', '/sql', '/mysql', '/wp-admin', '/wp-login.php',
             '/wp-content', '/manager', '/console', '/admin-console', '/test', '/testing', '/dev', '/development', '/logs',
             '/error_log', '/access_log', '/uploads', '/files', '/downloads', '/cgi-bin', '/cgi', '/cgi/test.cgi',
             '/.well-known', '/.well-known/security.txt', '/robots.txt', '/sitemap.xml', '/humans.txt']
    tech = recon_data.get('tech', [])
    if 'WordPress' in tech:
        paths.extend(['/wp-includes', '/wp-json', '/xmlrpc.php', '/license.txt'])
    if 'PHP' in tech:
        paths.extend(['/info.php', '/phpinfo.php', '/test.php'])
    if 'Laravel' in tech:
        paths.extend(['/storage', '/.env.example', '/artisan'])
    if 'Shopify' in tech:
        paths.extend(['/admin', '/cart', '/checkout', '/collections', '/products', '/account'])
    return paths

def main():
    signal.signal(signal.SIGINT, signal_handler)
    banner()
    args = parse_args()
    try:
        validate_args(args)
    except ValueError as e:
        print(f"{Fore.RED}[-] Argument error: {e}{Style.RESET_ALL}")
        sys.exit(1)
    logger = setup_logging(args)
    output = OutputFormatter(args.output, args.verbose, args.quiet, args.format)
    try:
        output.system_status("INITIATING SYSTEM SCAN", "boot_sequence")
        logger.info(f"Starting scan for {args.url}")
        plugin_manager = None
        if args.plugins and PLUGINS_AVAILABLE:
            output.system_status("LOADING NEURAL MODULES", "plugin_init")
            plugin_manager = PluginManager(args.plugins.split(','), args)
            plugin_manager.load_plugins()
        elif args.plugins and not PLUGINS_AVAILABLE:
            output.warning("Plugins requested but not available. Install plugins.py to use this feature.")
        output.system_status("PERFORMING RECONNAISSANCE", "recon_start")
        recon = AdvancedWebRecon(args.url, args.timeout, args.user_agent, args.proxy, args.cookies)
        recon_data = recon.analyze()
        if args.verbose:
            output.recon_summary(recon_data)
        paths = []
        if args.wordlist:
            output.system_status(f"LOADING WORDLIST: {args.wordlist}", "wordlist_load")
            try:
                with open(args.wordlist, 'r') as f:
                    paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                output.success(f"Loaded {len(paths)} paths from wordlist")
            except FileNotFoundError:
                output.error(f"Wordlist not found: {args.wordlist}")
                sys.exit(1)
        elif not args.no_ai:
            output.system_status(f"GENERATING AI PATHS - MODEL: {args.ai_model.upper()}", "ai_generation")
            ai_gen = EnhancedAIPathGenerator(model=args.ai_model, api_key=args.api_key)
            paths = ai_gen.generate_paths(recon_data, depth=args.depth)
            output.success(f"Generated {len(paths)} intelligent paths")
        else:
            output.system_status("USING BUILT-IN PATH DATABASE", "builtin_paths")
            paths = get_builtin_paths(recon_data)
        if args.extensions and not args.wordlist:
            paths_with_ext = []
            for path in paths:
                if '.' not in path.split('/')[-1]:
                    for ext in args.extensions.split(','):
                        paths_with_ext.append(f"{path}.{ext.strip()}")
            paths.extend(paths_with_ext)
            output.info(f"Added extensions: {args.extensions}")
        paths = sorted(list(set(paths)))
        output.info(f"Total unique paths to test: {len(paths)}")
        output.system_status(f"INITIATING PATH ENUMERATION - THREADS: {args.threads}", "scan_start")
        buster = EnhancedPathBuster(args.url, args.threads, args.timeout, args.delay, retries=args.retries, proxy=args.proxy,
                          cookies=args.cookies, rate_limit=args.rate_limit, user_agent=args.user_agent, headers=args.headers)
        results = buster.bust(paths, output)
        if plugin_manager:
            output.system_status("EXECUTING NEURAL MODULES", "plugin_run")
            plugin_results = plugin_manager.run_plugins(recon_data, results['results'])
            results['results']['plugin_results'] = plugin_results
        output.summary(results['results'])
        if args.output:
            output.save_results(results['results'])
            output.success(f"Results saved to {args.output}")
        if args.output and args.format:
            output.generate_report(results['results'], args.format)
        logger.info(f"Scan completed. Found {len(results['results']['found'])} accessible paths.")
    except KeyboardInterrupt:
        output.error("\nScan interrupted by user")
        logger.warning("Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        output.error(f"Error: {str(e)}")
        logger.error(f"Error during scan: {str(e)}", exc_info=True)
        if args.debug:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()