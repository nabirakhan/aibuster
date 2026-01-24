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
    """Clean, simple progress bar"""
    
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
        
        # Update every 0.5 seconds or at completion
        if now - self.last_print < 0.5 and current < self.total:
            return
        
        self.last_print = now
        self._render()
    
    def _render(self):
        """Render simple progress bar"""
        percent = (self.current / self.total) * 100
        bar_width = 30
        filled = int(bar_width * self.current / self.total)
        bar = '█' * filled + '░' * (bar_width - filled)
        
        # Calculate ETA
        elapsed = time.time() - self.start_time
        if self.current > 0:
            rate = self.current / elapsed
            remaining = (self.total - self.current) / rate if rate > 0 else 0
            eta = f"ETA: {self._format_time(remaining)}"
        else:
            eta = "ETA: calculating..."
        
        # Clean single-line progress
        sys.stdout.write(f"\r{Fore.CYAN}[{bar}]{Style.RESET_ALL} {percent:.0f}% | {self.current}/{self.total} | {eta}     ")
        sys.stdout.flush()
    
    def complete(self):
        """Mark as complete"""
        self.update(self.total)
        print()  # New line after completion
    
    def _format_time(self, seconds):
        """Format time nicely"""
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            return f"{seconds/60:.0f}m {seconds%60:.0f}s"
        else:
            return f"{seconds/3600:.0f}h {(seconds%3600)/60:.0f}m"

class OutputFormatter:
    """Beautiful, clean output formatter"""
    
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
    # SIMPLE STATUS MESSAGES
    # ═══════════════════════════════════════
    
    def status(self, msg):
        """Blue info message"""
        if not self.quiet:
            print(f"{Fore.CYAN}▶{Style.RESET_ALL} {msg}")
    
    def success(self, msg):
        """Green success message"""
        if not self.quiet:
            print(f"{Fore.GREEN}✓{Style.RESET_ALL} {msg}")
    
    def error(self, msg):
        """Red error message"""
        if not self.quiet:
            print(f"{Fore.RED}✗{Style.RESET_ALL} {msg}")
    
    def warning(self, msg):
        """Yellow warning message"""
        if not self.quiet:
            print(f"{Fore.YELLOW}⚠{Style.RESET_ALL} {msg}")
    
    def info(self, msg):
        """Gray info message (verbose only)"""
        if self.verbose and not self.quiet:
            print(f"{Fore.WHITE}  {msg}{Style.RESET_ALL}")
    
    # ═══════════════════════════════════════
    # CLEAN FINDING DISPLAY
    # ═══════════════════════════════════════
    
    def found(self, path, status, size, response_time=0, content_type=""):
        """Display found path - CLEAN & SIMPLE"""
        if self.quiet:
            return
        
        # Don't show 404s
        if status == 404:
            return
        
        # Simple status indicators
        if status == 200:
            icon = f"{Fore.GREEN}✓{Style.RESET_ALL}"
            self.findings['found'] += 1
        elif status == 403:
            icon = f"{Fore.RED}✗{Style.RESET_ALL}"
            self.findings['forbidden'] += 1
        elif status == 401:
            icon = f"{Fore.MAGENTA}🔒{Style.RESET_ALL}"
            self.findings['unauthorized'] += 1
        elif status in [301, 302]:
            icon = f"{Fore.YELLOW}→{Style.RESET_ALL}"
            self.findings['redirects'] += 1
        else:
            icon = "?"
        
        # Clean output format
        size_kb = size / 1024
        if size_kb < 1:
            size_str = f"{size}B"
        elif size_kb < 1024:
            size_str = f"{size_kb:.1f}KB"
        else:
            size_str = f"{size_kb/1024:.1f}MB"
        
        # Only show essentials
        print(f"{icon} {path:45} [{status}] {size_str:>8}")
    
    # ═══════════════════════════════════════
    # PROGRESS BAR
    # ═══════════════════════════════════════
    
    def create_progress_bar(self, total, description="Scanning"):
        """Create simple progress bar"""
        if not self.quiet:
            self.progress_bar = SimpleProgressBar(total, description)
            print(f"\n{Fore.CYAN}Starting scan...{Style.RESET_ALL}")
    
    def update_progress(self, current):
        """Update progress bar"""
        if self.progress_bar:
            self.progress_bar.update(current)
    
    def complete_progress(self):
        """Complete progress bar"""
        if self.progress_bar:
            self.progress_bar.complete()
            print()  # Extra spacing
    
    # ═══════════════════════════════════════
    # BEAUTIFUL SUMMARY
    # ═══════════════════════════════════════
    
    def summary(self, results):
        """Display beautiful summary"""
        if self.quiet:
            return
        
        duration = (datetime.now() - self.scan_start).total_seconds()
        
        # Header
        print(f"\n{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'SCAN COMPLETE':^60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}\n")
        
        # Results in a clean grid
        found = len(results.get('found', []))
        forbidden = len(results.get('forbidden', []))
        redirects = len(results.get('redirects', []))
        unauthorized = len(results.get('unauthorized', []))
        
        print(f"  {Fore.GREEN}✓ Found (200):{Style.RESET_ALL}        {found:>4}")
        print(f"  {Fore.YELLOW}→ Redirects:{Style.RESET_ALL}          {redirects:>4}")
        print(f"  {Fore.RED}✗ Forbidden (403):{Style.RESET_ALL}    {forbidden:>4}")
        print(f"  {Fore.MAGENTA}🔒 Unauthorized (401):{Style.RESET_ALL} {unauthorized:>4}")
        
        print(f"\n  {Fore.WHITE}⏱ Duration:{Style.RESET_ALL}           {duration:.1f}s")
        print(f"  {Fore.WHITE}📊 Total Tested:{Style.RESET_ALL}       {sum([found, forbidden, redirects, unauthorized])}")
        
        # Top 5 findings (if any)
        if found > 0:
            print(f"\n{Fore.CYAN}Top Findings:{Style.RESET_ALL}")
            top_results = sorted(results['found'], key=lambda x: x.get('size', 0), reverse=True)[:5]
            for i, result in enumerate(top_results, 1):
                path = result.get('path', '')[:40]
                size = result.get('size', 0)
                print(f"  {i}. {path:40} ({size:,} bytes)")
        
        print(f"\n{Fore.CYAN}{'═' * 60}{Style.RESET_ALL}\n")
    
    # ═══════════════════════════════════════
    # SAVE RESULTS (Unchanged - works well)
    # ═══════════════════════════════════════
    
    def save_results(self, results):
        """Save results to file"""
        if not self.output_file:
            return
        
        try:
            if self.format == "json":
                self._save_json(results)
            elif self.format == "csv":
                self._save_csv(results)
            elif self.format == "html":
                self._save_html(results)
            elif self.format == "xml":
                self._save_xml(results)
            elif self.format == "md":
                self._save_markdown(results)
            
            self.success(f"Results saved: {self.output_file}")
        except Exception as e:
            self.error(f"Save failed: {str(e)}")
    
    def _save_json(self, results):
        """Save as JSON"""
        output_data = {
            'metadata': {
                'tool': 'AIBuster',
                'version': '2.0.0',
                'timestamp': datetime.now().isoformat(),
                'duration': (datetime.now() - self.scan_start).total_seconds()
            },
            'results': results
        }
        
        with open(self.output_file, 'w') as f:
            json.dump(output_data, f, indent=2, default=str)
    
    def _save_csv(self, results):
        """Save as CSV"""
        with open(self.output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Path', 'Status', 'Size', 'Content-Type', 'URL'])
            
            for category in ['found', 'redirects', 'forbidden', 'unauthorized']:
                for item in results.get(category, []):
                    writer.writerow([
                        item.get('path', ''),
                        item.get('status', ''),
                        item.get('size', ''),
                        item.get('content_type', ''),
                        item.get('url', '')
                    ])
    
    def _save_html(self, results):
        """Save beautiful HTML report"""
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>AIBuster Scan Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }}
        .container {{ 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header p {{ opacity: 0.9; }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .stat-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            margin: 10px 0;
        }}
        .stat-card .label {{ color: #666; }}
        .success .number {{ color: #28a745; }}
        .warning .number {{ color: #ffc107; }}
        .danger .number {{ color: #dc3545; }}
        .info .number {{ color: #17a2b8; }}
        
        .results {{
            padding: 30px;
        }}
        .result-item {{
            background: #f8f9fa;
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        .result-item.success {{ border-left-color: #28a745; }}
        .result-item.danger {{ border-left-color: #dc3545; }}
        .result-item.warning {{ border-left-color: #ffc107; }}
        
        .path {{ 
            font-family: 'Courier New', monospace;
            font-weight: bold;
            font-size: 1.1em;
        }}
        .meta {{ 
            color: #666;
            font-size: 0.9em;
            margin-top: 5px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 AIBuster Scan Report</h1>
            <p>Security Assessment Results</p>
            <p style="margin-top: 10px; font-size: 0.9em;">
                {datetime.now().strftime('%B %d, %Y at %H:%M:%S')}
            </p>
        </div>
        
        <div class="stats">
            <div class="stat-card success">
                <div class="label">Found</div>
                <div class="number">{len(results.get('found', []))}</div>
            </div>
            <div class="stat-card warning">
                <div class="label">Redirects</div>
                <div class="number">{len(results.get('redirects', []))}</div>
            </div>
            <div class="stat-card danger">
                <div class="label">Forbidden</div>
                <div class="number">{len(results.get('forbidden', []))}</div>
            </div>
            <div class="stat-card info">
                <div class="label">Duration</div>
                <div class="number">{(datetime.now() - self.scan_start).total_seconds():.1f}s</div>
            </div>
        </div>
        
        <div class="results">
            <h2>📄 Detailed Results</h2>
"""
        
        # Add findings
        for category in ['found', 'redirects', 'forbidden']:
            items = results.get(category, [])
            if items:
                css_class = 'success' if category == 'found' else ('warning' if category == 'redirects' else 'danger')
                html_content += f"<h3>{category.title()} ({len(items)})</h3>"
                for item in items[:20]:  # Limit to 20 per category
                    path = html.escape(item.get('path', ''))
                    status = item.get('status', '')
                    size = item.get('size', 0)
                    html_content += f"""
                    <div class="result-item {css_class}">
                        <div class="path">{path}</div>
                        <div class="meta">Status: {status} | Size: {size:,} bytes</div>
                    </div>
                    """
        
        html_content += """
        </div>
    </div>
</body>
</html>
"""
        
        with open(self.output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def _save_xml(self, results):
        """Save as XML"""
        root = ET.Element("aibuster_scan")
        metadata = ET.SubElement(root, "metadata")
        ET.SubElement(metadata, "timestamp").text = datetime.now().isoformat()
        
        results_elem = ET.SubElement(root, "results")
        for category, items in results.items():
            if isinstance(items, list):
                cat_elem = ET.SubElement(results_elem, category)
                for item in items:
                    item_elem = ET.SubElement(cat_elem, "item")
                    for key, value in item.items():
                        ET.SubElement(item_elem, key).text = str(value)
        
        xml_str = ET.tostring(root, encoding='unicode')
        xml_pretty = minidom.parseString(xml_str).toprettyxml(indent="  ")
        
        with open(self.output_file, 'w') as f:
            f.write(xml_pretty)
    
    def _save_markdown(self, results):
        """Save as Markdown"""
        md = f"""# AIBuster Scan Report

**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Duration:** {(datetime.now() - self.scan_start).total_seconds():.1f}s

## Summary

| Category | Count |
|----------|-------|
| ✓ Found | {len(results.get('found', []))} |
| → Redirects | {len(results.get('redirects', []))} |
| ✗ Forbidden | {len(results.get('forbidden', []))} |

## Results\n"""
        
        for category in ['found', 'redirects', 'forbidden']:
            items = results.get(category, [])
            if items:
                md += f"\n### {category.title()}\n\n"
                for item in items:
                    path = item.get('path', '')
                    status = item.get('status', '')
                    md += f"- `{path}` - Status: {status}\n"
        
        with open(self.output_file, 'w') as f:
            f.write(md)
    
    def generate_report(self, results, format_override=None):
        """Generate report in specified format"""
        self.save_results(results)