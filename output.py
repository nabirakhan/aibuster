import json
import csv
import xml.etree.ElementTree as ET
from xml.dom import minidom
from datetime import datetime
import sys
import time
from colorama import Fore, Style, Back
import html
from typing import Dict, List, Any

class OutputFormat:
    JSON = "json"
    CSV = "csv"
    HTML = "html"
    XML = "xml"
    MARKDOWN = "md"

class SimpleProgressBar:
    """Vibrant progress bar with gradient colors"""
    
    def __init__(self, total, description="Scanning"):
        self.total = total
        self.description = description
        self.start_time = time.time()
        self.current = 0
        self.last_print = 0
        
    def update(self, current):
        """Update progress"""
        self.current = current
        now = time.time()
        
        if now - self.last_print < 0.3 and current < self.total:
            return
        
        self.last_print = now
        self._render()
    
    def _render(self):
        """Render colorful progress bar"""
        percent = (self.current / self.total) * 100
        bar_width = 40
        filled = int(bar_width * self.current / self.total)
        
        # Gradient colors based on progress
        if percent < 33:
            bar_color = Fore.RED
        elif percent < 66:
            bar_color = Fore.YELLOW
        else:
            bar_color = Fore.GREEN
        
        bar = '█' * filled + '░' * (bar_width - filled)
        
        # Calculate stats
        elapsed = time.time() - self.start_time
        if self.current > 0:
            rate = self.current / elapsed
            remaining = (self.total - self.current) / rate if rate > 0 else 0
            eta = f"{self._format_time(remaining)}"
            rps = f"{rate:.1f} req/s"
        else:
            eta = "calculating..."
            rps = "0.0 req/s"
        
        # Colorful output
        sys.stdout.write(f"\r{Fore.CYAN}[{bar_color}{bar}{Fore.CYAN}]{Style.RESET_ALL} {Fore.MAGENTA}{percent:5.1f}%{Style.RESET_ALL} | {Fore.CYAN}{self.current}{Style.RESET_ALL}/{Fore.CYAN}{self.total}{Style.RESET_ALL} | {Fore.YELLOW}{rps}{Style.RESET_ALL} | ETA: {Fore.GREEN}{eta}{Style.RESET_ALL}    ")
        sys.stdout.flush()
    
    def complete(self):
        """Mark as complete"""
        self.update(self.total)
        print()
    
    def _format_time(self, seconds):
        """Format time"""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            return f"{seconds/60:.0f}m"
        else:
            return f"{seconds/3600:.0f}h"

class OutputFormatter:
    """Vibrant color-coded output formatter - WraithXSS style"""
    
    def __init__(self, output_file=None, verbose=False, quiet=False, format="json"):
        self.output_file = output_file
        self.verbose = verbose
        self.quiet = quiet
        self.format = format
        self.progress_bar = None
        self.scan_start = datetime.now()
        
        # Track findings
        self.findings = {
            'found': 0,
            'forbidden': 0,
            'redirects': 0,
            'unauthorized': 0
        }
    
    # ═══════════════════════════════════════
    # VIBRANT STATUS MESSAGES
    # ═══════════════════════════════════════
    
    def system_status(self, msg, status_type="info"):
        """Colorful system status messages"""
        if not self.quiet:
            timestamp = datetime.now().strftime("%H:%M:%S")
            
            if status_type == "boot_sequence":
                print(f"\n{Fore.GREEN}[{Fore.WHITE}+{Fore.GREEN}]{Style.RESET_ALL} {Fore.CYAN}[{timestamp}]{Style.RESET_ALL} {Fore.GREEN}{msg}{Style.RESET_ALL}")
            elif status_type == "recon_start":
                print(f"{Fore.CYAN}[{Fore.WHITE}*{Fore.CYAN}]{Style.RESET_ALL} {Fore.CYAN}[{timestamp}]{Style.RESET_ALL} {Fore.CYAN}{msg}{Style.RESET_ALL}")
            elif status_type == "ai_generation":
                print(f"{Fore.MAGENTA}[{Fore.WHITE}~{Fore.MAGENTA}]{Style.RESET_ALL} {Fore.CYAN}[{timestamp}]{Style.RESET_ALL} {Fore.MAGENTA}{msg}{Style.RESET_ALL}")
            elif status_type == "scan_start":
                print(f"{Fore.YELLOW}[{Fore.WHITE}>{Fore.YELLOW}]{Style.RESET_ALL} {Fore.CYAN}[{timestamp}]{Style.RESET_ALL} {Fore.YELLOW}{msg}{Style.RESET_ALL}")
            elif status_type == "plugin_init" or status_type == "plugin_run":
                print(f"{Fore.BLUE}[{Fore.WHITE}#{Fore.BLUE}]{Style.RESET_ALL} {Fore.CYAN}[{timestamp}]{Style.RESET_ALL} {Fore.BLUE}{msg}{Style.RESET_ALL}")
            elif status_type == "wordlist_load":
                print(f"{Fore.YELLOW}[{Fore.WHITE}@{Fore.YELLOW}]{Style.RESET_ALL} {Fore.CYAN}[{timestamp}]{Style.RESET_ALL} {Fore.YELLOW}{msg}{Style.RESET_ALL}")
            elif status_type == "builtin_paths":
                print(f"{Fore.WHITE}[{Fore.CYAN}i{Fore.WHITE}]{Style.RESET_ALL} {Fore.CYAN}[{timestamp}]{Style.RESET_ALL} {Fore.WHITE}{msg}{Style.RESET_ALL}")
            else:
                print(f"{Fore.WHITE}[{Fore.CYAN}i{Fore.WHITE}]{Style.RESET_ALL} {Fore.CYAN}[{timestamp}]{Style.RESET_ALL} {Fore.WHITE}{msg}{Style.RESET_ALL}")
    
    def status(self, msg):
        """Cyan info message"""
        if not self.quiet:
            print(f"{Fore.CYAN}[{Fore.WHITE}*{Fore.CYAN}]{Style.RESET_ALL} {msg}")
    
    def success(self, msg):
        """Green success message"""
        if not self.quiet:
            print(f"{Fore.GREEN}[{Fore.WHITE}+{Fore.GREEN}]{Style.RESET_ALL} {Fore.GREEN}{msg}{Style.RESET_ALL}")
    
    def error(self, msg):
        """Red error message"""
        if not self.quiet:
            print(f"{Fore.RED}[{Fore.WHITE}-{Fore.RED}]{Style.RESET_ALL} {Fore.RED}{msg}{Style.RESET_ALL}")
    
    def warning(self, msg):
        """Yellow warning message"""
        if not self.quiet:
            print(f"{Fore.YELLOW}[{Fore.WHITE}!{Fore.YELLOW}]{Style.RESET_ALL} {Fore.YELLOW}{msg}{Style.RESET_ALL}")
    
    def info(self, msg):
        """White info message (verbose only)"""
        if self.verbose and not self.quiet:
            print(f"{Fore.WHITE}[{Fore.CYAN}i{Fore.WHITE}]{Style.RESET_ALL} {msg}")
    
    # ═══════════════════════════════════════
    # COLORFUL RECONNAISSANCE SUMMARY
    # ═══════════════════════════════════════
    
    def recon_summary(self, recon_data):
        """Display colorful reconnaissance summary"""
        if self.quiet:
            return
        
        print(f"\n{Fore.CYAN}{'═' * 80}")
        print(f"{Fore.MAGENTA}{'» RECONNAISSANCE SUMMARY «':^80}")
        print(f"{Fore.CYAN}{'═' * 80}{Style.RESET_ALL}\n")
        
        print(f"{Fore.GREEN}[+] {Fore.WHITE}Target Information:{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}URL:{Style.RESET_ALL}             {Fore.WHITE}{recon_data.get('url', 'N/A')}{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}Status Code:{Style.RESET_ALL}     {self._colorize_status(recon_data.get('status_code', 0))}")
        print(f"    {Fore.CYAN}Response Time:{Style.RESET_ALL}   {Fore.YELLOW}{recon_data.get('response_time', 0):.3f}s{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}Page Size:{Style.RESET_ALL}       {Fore.MAGENTA}{recon_data.get('page_size', 0):,} bytes{Style.RESET_ALL}")
        
        if recon_data.get('page_title'):
            print(f"    {Fore.CYAN}Page Title:{Style.RESET_ALL}      {Fore.WHITE}{recon_data.get('page_title', 'N/A')[:60]}{Style.RESET_ALL}")
        
        tech = recon_data.get('tech', [])
        if tech:
            print(f"\n{Fore.GREEN}[+] {Fore.WHITE}Technologies Detected:{Style.RESET_ALL}")
            for i, t in enumerate(tech[:10], 1):
                print(f"    {Fore.YELLOW}[{i:02d}]{Style.RESET_ALL} {Fore.CYAN}{t}{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[+] {Fore.WHITE}Resources Found:{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}Links:{Style.RESET_ALL}           {Fore.MAGENTA}{len(recon_data.get('links', []))}{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}Scripts:{Style.RESET_ALL}         {Fore.MAGENTA}{len(recon_data.get('scripts', []))}{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}Forms:{Style.RESET_ALL}           {Fore.MAGENTA}{len(recon_data.get('forms', []))}{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}Keywords:{Style.RESET_ALL}        {Fore.MAGENTA}{len(recon_data.get('keywords', []))}{Style.RESET_ALL}")
        
        security_headers = recon_data.get('security_headers', {})
        if security_headers:
            print(f"\n{Fore.GREEN}[+] {Fore.WHITE}Security Headers:{Style.RESET_ALL}")
            for header, value in list(security_headers.items())[:5]:
                print(f"    {Fore.GREEN}✓{Style.RESET_ALL} {Fore.CYAN}{header}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'═' * 80}{Style.RESET_ALL}\n")
    
    def _colorize_status(self, status):
        """Colorize status codes"""
        if status == 200:
            return f"{Fore.GREEN}{status}{Style.RESET_ALL}"
        elif status in [301, 302, 303, 307, 308]:
            return f"{Fore.YELLOW}{status}{Style.RESET_ALL}"
        elif status == 403:
            return f"{Fore.RED}{status}{Style.RESET_ALL}"
        elif status == 401:
            return f"{Fore.MAGENTA}{status}{Style.RESET_ALL}"
        elif status == 404:
            return f"{Fore.WHITE}{status}{Style.RESET_ALL}"
        else:
            return f"{Fore.CYAN}{status}{Style.RESET_ALL}"
    
    # ═══════════════════════════════════════
    # VIBRANT FINDING DISPLAY
    # ═══════════════════════════════════════
    
    def found(self, path, status, size, response_time=0, content_type=""):
        """Display found path with vibrant colors - WraithXSS style"""
        if self.quiet:
            return
        
        # Don't show 404s
        if status == 404:
            return
        
        # Color-coded status indicators
        if status == 200:
            icon = f"{Fore.GREEN}[{Fore.WHITE}✓{Fore.GREEN}]{Style.RESET_ALL}"
            status_str = f"{Fore.GREEN}200{Style.RESET_ALL}"
            path_color = Fore.WHITE
            self.findings['found'] += 1
            
        elif status == 403:
            icon = f"{Fore.RED}[{Fore.WHITE}✗{Fore.RED}]{Style.RESET_ALL}"
            status_str = f"{Fore.RED}403{Style.RESET_ALL}"
            path_color = Fore.RED
            self.findings['forbidden'] += 1
            
        elif status == 401:
            icon = f"{Fore.MAGENTA}[{Fore.WHITE}!{Fore.MAGENTA}]{Style.RESET_ALL}"
            status_str = f"{Fore.MAGENTA}401{Style.RESET_ALL}"
            path_color = Fore.MAGENTA
            self.findings['unauthorized'] += 1
            
        elif status in [301, 302, 307, 308]:
            icon = f"{Fore.YELLOW}[{Fore.WHITE}→{Fore.YELLOW}]{Style.RESET_ALL}"
            status_str = f"{Fore.YELLOW}{status}{Style.RESET_ALL}"
            path_color = Fore.YELLOW
            self.findings['redirects'] += 1
            
        else:
            icon = f"{Fore.CYAN}[{Fore.WHITE}?{Fore.CYAN}]{Style.RESET_ALL}"
            status_str = f"{Fore.CYAN}{status}{Style.RESET_ALL}"
            path_color = Fore.CYAN
        
        # Format size with color
        if size < 1024:
            size_str = f"{Fore.CYAN}{size}B{Style.RESET_ALL}"
        elif size < 1024 * 1024:
            size_str = f"{Fore.MAGENTA}{size/1024:.1f}KB{Style.RESET_ALL}"
        else:
            size_str = f"{Fore.RED}{size/(1024*1024):.1f}MB{Style.RESET_ALL}"
        
        # Colorful path display
        path_display = f"{path_color}{path}{Style.RESET_ALL}"
        
        # Beautiful WraithXSS-style output
        print(f"{icon} {path_display:<60} [{status_str}] [Size: {size_str}]")
    
    # ═══════════════════════════════════════
    # PROGRESS BAR
    # ═══════════════════════════════════════
    
    def create_progress_bar(self, total, description="Scanning"):
        """Create colorful progress bar"""
        if not self.quiet:
            self.progress_bar = SimpleProgressBar(total, description)
            print(f"\n{Fore.CYAN}[{Fore.WHITE}*{Fore.CYAN}]{Style.RESET_ALL} {Fore.CYAN}Starting path enumeration...{Style.RESET_ALL}\n")
    
    def update_progress(self, current):
        """Update progress bar"""
        if self.progress_bar:
            self.progress_bar.update(current)
    
    def complete_progress(self):
        """Complete progress bar"""
        if self.progress_bar:
            self.progress_bar.complete()
            print()
    
    # ═══════════════════════════════════════
    # COLORFUL SUMMARY
    # ═══════════════════════════════════════
    
    def summary(self, results):
        """Display vibrant summary"""
        if self.quiet:
            return
        
        duration = (datetime.now() - self.scan_start).total_seconds()
        
        # Colorful header
        print(f"\n{Fore.CYAN}{'═' * 80}")
        print(f"{Fore.GREEN}{'» SCAN COMPLETE «':^80}")
        print(f"{Fore.CYAN}{'═' * 80}{Style.RESET_ALL}\n")
        
        # Colorful results summary
        found = len(results.get('found', []))
        forbidden = len(results.get('forbidden', []))
        redirects = len(results.get('redirects', []))
        unauthorized = len(results.get('unauthorized', []))
        total_tested = sum([found, forbidden, redirects, unauthorized])
        
        print(f"{Fore.GREEN}[+] {Fore.WHITE}Results Summary:{Style.RESET_ALL}")
        print(f"    {Fore.GREEN}✓ Found (200):{Style.RESET_ALL}           {Fore.GREEN}{found:>5}{Style.RESET_ALL}")
        print(f"    {Fore.YELLOW}→ Redirects (3xx):{Style.RESET_ALL}      {Fore.YELLOW}{redirects:>5}{Style.RESET_ALL}")
        print(f"    {Fore.RED}✗ Forbidden (403):{Style.RESET_ALL}      {Fore.RED}{forbidden:>5}{Style.RESET_ALL}")
        print(f"    {Fore.MAGENTA}! Unauthorized (401):{Style.RESET_ALL}  {Fore.MAGENTA}{unauthorized:>5}{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}{'─' * 30}{Style.RESET_ALL}")
        print(f"    {Fore.WHITE}Total Results:{Style.RESET_ALL}        {Fore.CYAN}{total_tested:>5}{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}[+] {Fore.WHITE}Performance Metrics:{Style.RESET_ALL}")
        print(f"    {Fore.CYAN}Duration:{Style.RESET_ALL}             {Fore.YELLOW}{duration:.2f}s{Style.RESET_ALL}")
        if duration > 0:
            rps = total_tested / duration
            print(f"    {Fore.CYAN}Requests/sec:{Style.RESET_ALL}         {Fore.MAGENTA}{rps:.2f}{Style.RESET_ALL}")
        
        # Top findings with colors
        if found > 0:
            print(f"\n{Fore.GREEN}[+] {Fore.WHITE}Top Findings:{Style.RESET_ALL}")
            top_results = sorted(results['found'], key=lambda x: x.get('size', 0), reverse=True)[:10]
            for i, result in enumerate(top_results, 1):
                path = result.get('path', '')[:45]
                size = result.get('size', 0)
                if size < 1024:
                    size_str = f"{Fore.CYAN}{size}B{Style.RESET_ALL}"
                elif size < 1024 * 1024:
                    size_str = f"{Fore.MAGENTA}{size/1024:.1f}KB{Style.RESET_ALL}"
                else:
                    size_str = f"{Fore.RED}{size/(1024*1024):.1f}MB{Style.RESET_ALL}"
                print(f"    {Fore.YELLOW}[{i:>2}]{Style.RESET_ALL} {Fore.CYAN}{path:<45}{Style.RESET_ALL} [{size_str}]")
        
        # Interesting findings highlighted
        interesting = []
        for result in results.get('found', []):
            path = result.get('path', '').lower()
            if any(keyword in path for keyword in ['admin', 'login', 'config', 'backup', 'api', '.env', '.git', 'password', 'secret']):
                interesting.append(result)
        
        if interesting:
            print(f"\n{Fore.RED}[!] {Fore.WHITE}Critical/Interesting Paths:{Style.RESET_ALL}")
            for i, result in enumerate(interesting[:10], 1):
                path = result.get('path', '')
                status = result.get('status', 0)
                status_colored = self._colorize_status(status)
                
                # Highlight critical keywords
                if any(kw in path.lower() for kw in ['.env', 'password', 'secret', 'key']):
                    print(f"    {Fore.RED}[{i:>2}] {Fore.RED}{path:<50}{Style.RESET_ALL} [Status: {status_colored}] {Fore.RED}⚠ CRITICAL{Style.RESET_ALL}")
                else:
                    print(f"    {Fore.YELLOW}[{i:>2}] {Fore.YELLOW}{path:<50}{Style.RESET_ALL} [Status: {status_colored}]")
        
        print(f"\n{Fore.CYAN}{'═' * 80}{Style.RESET_ALL}\n")
    
    # ═══════════════════════════════════════
    # SAVE RESULTS (Simplified)
    # ═══════════════════════════════════════
    
    def save_results(self, results):
        """Save results to file"""
        if not self.output_file:
            return
        
        ext = self.output_file.split('.')[-1].lower()
        
        if ext == 'json' or self.format == 'json':
            self._save_json(results)
        elif ext == 'csv' or self.format == 'csv':
            self._save_csv(results)
        elif ext in ['html', 'htm'] or self.format == 'html':
            self._save_html(results)
        elif ext == 'xml' or self.format == 'xml':
            self._save_xml(results)
        elif ext == 'md' or self.format == 'md':
            self._save_markdown(results)
        else:
            self._save_json(results)
    
    def _save_json(self, results):
        output_data = {
            'metadata': {'tool': 'AIBuster', 'version': '2.5.0', 'timestamp': datetime.now().isoformat()},
            'results': results
        }
        with open(self.output_file, 'w') as f:
            json.dump(output_data, f, indent=2, default=str)
    
    def _save_csv(self, results):
        with open(self.output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Path', 'Status', 'Size', 'URL'])
            for category in ['found', 'redirects', 'forbidden', 'unauthorized']:
                for item in results.get(category, []):
                    writer.writerow([item.get('path'), item.get('status'), item.get('size'), item.get('url')])
    
    def _save_html(self, results):
        """Vibrant HTML report - WraithXSS style"""
        html_content = f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>AIBuster Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box;}}
body{{font-family:'Consolas',monospace;background:#0a0e27;color:#00ff41;padding:20px;}}
.container{{max-width:1400px;margin:0 auto;background:linear-gradient(135deg,#1a1d2e,#16213e);border-radius:10px;border:2px solid #00ff41;box-shadow:0 0 40px rgba(0,255,65,0.3);}}
.header{{background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;padding:50px;text-align:center;}}
.header h1{{font-size:3em;text-shadow:0 0 20px rgba(255,255,255,0.5);}}
.stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:25px;padding:40px;background:#0f1419;}}
.stat-card{{background:linear-gradient(135deg,#1a1d2e,#2a2d3e);padding:30px;border-radius:10px;text-align:center;border-top:3px solid var(--card-color);}}
.stat-card .number{{font-size:3em;font-weight:bold;margin:15px 0;color:var(--card-color);text-shadow:0 0 10px var(--card-color);}}
.stat-card .label{{color:#888;font-size:1.1em;text-transform:uppercase;}}
.success{{--card-color:#00ff41;}}
.warning{{--card-color:#ffaa00;}}
.danger{{--card-color:#ff4136;}}
.info{{--card-color:#00d4ff;}}
.results{{padding:40px;background:#0f1419;}}
.results h2{{color:#00ff41;margin-bottom:25px;padding-bottom:15px;border-bottom:3px solid #00ff41;font-size:2em;text-shadow:0 0 10px rgba(0,255,65,0.5);}}
.result-item{{background:linear-gradient(135deg,#1a1d2e,#2a2d3e);padding:18px 25px;margin:12px 0;border-radius:8px;border-left:5px solid var(--item-color);}}
.result-item.success{{--item-color:#00ff41;}}
.result-item.danger{{--item-color:#ff4136;}}
.result-item.warning{{--item-color:#ffaa00;}}
.path{{font-weight:bold;font-size:1.2em;color:var(--item-color);text-shadow:0 0 5px var(--item-color);}}
.meta{{color:#888;font-size:0.95em;margin-top:10px;}}
</style></head><body><div class="container">
<div class="header"><h1>⚡ AIBuster Scan ⚡</h1><p>AI-Powered Security Report</p><p>{datetime.now().strftime('%B %d, %Y at %H:%M:%S')}</p></div>
<div class="stats">
<div class="stat-card success"><div class="label">✓ Found</div><div class="number">{len(results.get('found',[]))}</div></div>
<div class="stat-card warning"><div class="label">→ Redirects</div><div class="number">{len(results.get('redirects',[]))}</div></div>
<div class="stat-card danger"><div class="label">✗ Forbidden</div><div class="number">{len(results.get('forbidden',[]))}</div></div>
<div class="stat-card info"><div class="label">⏱ Duration</div><div class="number">{(datetime.now()-self.scan_start).total_seconds():.1f}s</div></div>
</div><div class="results"><h2>⚡ Results</h2>"""
        for cat in ['found','redirects','forbidden']:
            items = results.get(cat,[])
            if items:
                css = 'success' if cat=='found' else ('warning' if cat=='redirects' else 'danger')
                html_content += f"<h3 style='color:#00ff41;margin-top:40px;'>{cat.upper()} ({len(items)})</h3>"
                for item in items[:50]:
                    path = html.escape(item.get('path',''))
                    status = item.get('status','')
                    size = item.get('size',0)
                    html_content += f'<div class="result-item {css}"><div class="path">[{status}] {path}</div><div class="meta">Size: {size:,} bytes</div></div>'
        html_content += '</div></div></body></html>'
        with open(self.output_file,'w',encoding='utf-8') as f:
            f.write(html_content)
    
    def _save_xml(self, results):
        root = ET.Element("aibuster_scan")
        ET.SubElement(ET.SubElement(root,"metadata"),"timestamp").text = datetime.now().isoformat()
        with open(self.output_file,'w') as f:
            f.write(minidom.parseString(ET.tostring(root)).toprettyxml(indent="  "))
    
    def _save_markdown(self, results):
        md = f"""# ⚡ AIBuster Report\n**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n## Results\n"""
        for cat in ['found','redirects','forbidden']:
            items = results.get(cat,[])
            if items:
                md += f"\n### {cat.upper()}\n"
                for item in items:
                    md += f"- `[{item.get('status')}]` {item.get('path')} - {item.get('size',0):,} bytes\n"
        with open(self.output_file,'w') as f:
            f.write(md)
    
    def generate_report(self, results, format_override=None):
        self.save_results(results)