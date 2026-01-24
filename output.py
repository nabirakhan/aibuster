"""
Enhanced output formatting module with progress bars and multiple formats
"""

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
from dataclasses import dataclass, asdict
from enum import Enum

class OutputFormat(Enum):
    JSON = "json"
    CSV = "csv"
    HTML = "html"
    XML = "xml"
    TXT = "txt"
    MARKDOWN = "md"

@dataclass
class ScanResult:
    """Data class for scan results"""
    url: str
    path: str
    status_code: int
    content_length: int
    response_time: float
    content_type: str = ""
    title: str = ""
    redirect_location: str = ""
    discovered_at: str = ""
    tags: List[str] = None
    
    def __post_init__(self):
        if self.tags is None:
            self.tags = []
        if not self.discovered_at:
            self.discovered_at = datetime.now().isoformat()

class ProgressBar:
    """Customizable progress bar"""
    
    def __init__(self, total, description="Progress", bar_length=50, 
                 show_percentage=True, show_time=True):
        self.total = total
        self.description = description
        self.bar_length = bar_length
        self.show_percentage = show_percentage
        self.show_time = show_time
        self.start_time = time.time()
        self.current = 0
        self.last_update = 0
        
    def update(self, current):
        """Update progress bar"""
        self.current = current
        now = time.time()
        
        # Throttle updates to avoid flickering
        if now - self.last_update < 0.1 and current < self.total:
            return
        
        self.last_update = now
        self._render()
    
    def _render(self):
        """Render progress bar"""
        percent = self.current / self.total
        filled_length = int(self.bar_length * percent)
        
        bar = '█' * filled_length + '░' * (self.bar_length - filled_length)
        
        # Build status string
        status_parts = []
        
        if self.show_time:
            elapsed = time.time() - self.start_time
            if self.current > 0:
                remaining = (elapsed / self.current) * (self.total - self.current)
                status_parts.append(f"Time: {self._format_time(elapsed)}/{self._format_time(remaining)}")
            else:
                status_parts.append(f"Time: {self._format_time(elapsed)}")
        
        if self.show_percentage:
            status_parts.append(f"{percent:.1%}")
        
        status_str = " | ".join(status_parts)
        
        # Print progress bar
        sys.stdout.write(f"\r{Fore.CYAN}{self.description}:{Style.RESET_ALL} "
                        f"{Fore.GREEN}[{bar}]{Style.RESET_ALL} "
                        f"{self.current}/{self.total} "
                        f"{status_str}")
        sys.stdout.flush()
    
    def complete(self):
        """Mark progress as complete"""
        self.update(self.total)
        print()
    
    def _format_time(self, seconds):
        """Format seconds into readable time"""
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        else:
            return f"{seconds/3600:.1f}h"

class OutputFormatter:
    """Enhanced output formatter with multiple formats"""
    
    def __init__(self, output_file=None, verbose=False, quiet=False, 
                 format="json", show_progress=True):
        self.output_file = output_file
        self.verbose = verbose
        self.quiet = quiet
        self.format = OutputFormat(format)
        self.show_progress = show_progress
        self.progress_bar = None
        self.scan_start = datetime.now()
        
        # Results storage
        self.results = {
            'found': [],
            'forbidden': [],
            'redirects': [],
            'errors': [],
            'warnings': []
        }
    
    def status(self, msg):
        """Print status message"""
        if not self.quiet:
            print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {msg}")
    
    def success(self, msg):
        """Print success message"""
        if not self.quiet:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
    
    def error(self, msg):
        """Print error message"""
        if not self.quiet:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")
    
    def warning(self, msg):
        """Print warning message"""
        if not self.quiet:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
    
    def info(self, msg):
        """Print info message"""
        if self.verbose and not self.quiet:
            print(f"{Fore.CYAN}[i]{Style.RESET_ALL} {msg}")
    
    def found(self, path, status, size, response_time=0, content_type=""):
        """Print found path with enhanced information"""
        if self.quiet:
            return
        
        # Determine color based on status code
        if status == 200:
            color = Fore.GREEN
            symbol = "[+]"
            status_text = "FOUND"
        elif status in [301, 302, 307, 308]:
            color = Fore.YELLOW
            symbol = "[→]"
            status_text = "REDIRECT"
        elif status == 403:
            color = Fore.RED
            symbol = "[✗]"
            status_text = "FORBIDDEN"
        elif status == 401:
            color = Fore.MAGENTA
            symbol = "[🔐]"
            status_text = "UNAUTHORIZED"
        elif status == 404:
            return  # Don't display 404s unless verbose
        else:
            color = Fore.WHITE
            symbol = "[?]"
            status_text = f"CODE {status}"
        
        # Format the output
        size_str = f"{size:,} bytes".rjust(12)
        time_str = f"{response_time:.2f}s".rjust(8) if response_time > 0 else ""
        
        if content_type:
            content_type = f" [{content_type[:20]}]"
        
        print(f"{color}{symbol}{Style.RESET_ALL} {path:50} "
              f"{color}{status_text:12}{Style.RESET_ALL} "
              f"{size_str}{time_str}{content_type}")
    
    def create_progress_bar(self, total, description="Scanning"):
        """Create a progress bar"""
        if self.show_progress and not self.quiet:
            self.progress_bar = ProgressBar(
                total=total,
                description=description,
                bar_length=40,
                show_percentage=True,
                show_time=True
            )
    
    def update_progress(self, current):
        """Update progress bar"""
        if self.progress_bar:
            self.progress_bar.update(current)
    
    def complete_progress(self):
        """Complete progress bar"""
        if self.progress_bar:
            self.progress_bar.complete()
    
    def summary(self, results):
        """Print detailed summary"""
        if self.quiet:
            return
        
        scan_duration = datetime.now() - self.scan_start
        
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}SCAN SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        # Results breakdown
        print(f"{Fore.GREEN}✓ Found (200):{Style.RESET_ALL} {len(results['found'])}")
        print(f"{Fore.YELLOW}→ Redirects:{Style.RESET_ALL} {len(results['redirects'])}")
        print(f"{Fore.RED}✗ Forbidden (403):{Style.RESET_ALL} {len(results['forbidden'])}")
        print(f"{Fore.MAGENTA}🔐 Unauthorized (401):{Style.RESET_ALL} {len([r for r in results['found'] if r.get('status') == 401])}")
        
        # Statistics
        total_tested = sum(len(v) for v in results.values() if isinstance(v, list))
        success_rate = (len(results['found']) / total_tested * 100) if total_tested > 0 else 0
        
        print(f"\n{Fore.CYAN}Statistics:{Style.RESET_ALL}")
        print(f"  Total paths tested: {total_tested}")
        print(f"  Success rate: {success_rate:.1f}%")
        print(f"  Scan duration: {scan_duration.total_seconds():.1f} seconds")
        
        # Top findings
        if results['found']:
            print(f"\n{Fore.CYAN}Top Findings:{Style.RESET_ALL}")
            for result in sorted(results['found'], key=lambda x: x.get('size', 0), reverse=True)[:5]:
                path = result.get('path', '')
                status = result.get('status', 0)
                size = result.get('size', 0)
                print(f"  {path:40} {status} ({size:,} bytes)")
        
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    def save_results(self, results, format_override=None):
        """Save results in specified format"""
        if not self.output_file:
            return
        
        format_to_use = format_override or self.format
        
        try:
            if format_to_use == OutputFormat.JSON:
                self._save_json(results)
            elif format_to_use == OutputFormat.CSV:
                self._save_csv(results)
            elif format_to_use == OutputFormat.HTML:
                self._save_html(results)
            elif format_to_use == OutputFormat.XML:
                self._save_xml(results)
            elif format_to_use == OutputFormat.MARKDOWN:
                self._save_markdown(results)
            else:
                self._save_text(results)
            
            self.success(f"Results saved to {self.output_file}")
            
        except Exception as e:
            self.error(f"Failed to save results: {str(e)}")
    
    def _save_json(self, results):
        """Save results as JSON"""
        output_data = {
            'metadata': {
                'tool': 'AIBuster',
                'version': '2.0.0',
                'timestamp': datetime.now().isoformat(),
                'url': results.get('target_url', ''),
                'duration': (datetime.now() - self.scan_start).total_seconds()
            },
            'results': results
        }
        
        with open(self.output_file, 'w') as f:
            json.dump(output_data, f, indent=2, default=str)
    
    def _save_csv(self, results):
        """Save results as CSV"""
        with open(self.output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow(['Path', 'Status', 'Size', 'Content-Type', 'URL', 'Discovered'])
            
            # Write all found paths
            for category in ['found', 'redirects', 'forbidden']:
                for item in results.get(category, []):
                    writer.writerow([
                        item.get('path', ''),
                        item.get('status', ''),
                        item.get('size', ''),
                        item.get('content_type', ''),
                        item.get('url', ''),
                        datetime.now().isoformat()
                    ])
    
    def _save_html(self, results):
        """Save results as HTML report"""
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>AIBuster Scan Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }}
        .summary {{ background: #e8f5e9; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .result {{ padding: 10px; border-left: 4px solid #4CAF50; margin: 5px 0; background: #f9f9f9; }}
        .status-200 {{ border-color: #4CAF50; }}
        .status-301 {{ border-color: #FFC107; }}
        .status-302 {{ border-color: #FFC107; }}
        .status-403 {{ border-color: #F44336; }}
        .status-401 {{ border-color: #9C27B0; }}
        .metadata {{ color: #666; font-size: 0.9em; }}
        .path {{ font-weight: bold; font-family: monospace; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 0.8em; color: white; margin-right: 5px; }}
        .badge-success {{ background: #4CAF50; }}
        .badge-warning {{ background: #FFC107; }}
        .badge-danger {{ background: #F44336; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 AIBuster Scan Report</h1>
        
        <div class="metadata">
            <p><strong>Target URL:</strong> {results.get('target_url', 'N/A')}</p>
            <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Duration:</strong> {(datetime.now() - self.scan_start).total_seconds():.1f} seconds</p>
        </div>
        
        <div class="summary">
            <h3>📊 Summary</h3>
            <p>Found (200): <span class="badge badge-success">{len(results.get('found', []))}</span></p>
            <p>Redirects: <span class="badge badge-warning">{len(results.get('redirects', []))}</span></p>
            <p>Forbidden (403): <span class="badge badge-danger">{len(results.get('forbidden', []))}</span></p>
        </div>
        
        <h3>📄 Results</h3>"""
        
        # Add results
        for category, items in results.items():
            if isinstance(items, list) and items:
                html_content += f"<h4>{category.title()}</h4>"
                for item in items:
                    status = item.get('status', 0)
                    html_content += f"""
                    <div class="result status-{status}">
                        <div class="path">{html.escape(item.get('path', ''))}</div>
                        <div>Status: <strong>{status}</strong> | Size: {item.get('size', 0):,} bytes</div>
                        <div>URL: {html.escape(item.get('url', ''))}</div>
                    </div>"""
        
        html_content += """
    </div>
</body>
</html>"""
        
        with open(self.output_file, 'w') as f:
            f.write(html_content)
    
    def _save_xml(self, results):
        """Save results as XML"""
        root = ET.Element("aibuster_scan")
        
        # Metadata
        metadata = ET.SubElement(root, "metadata")
        ET.SubElement(metadata, "tool").text = "AIBuster"
        ET.SubElement(metadata, "version").text = "2.0.0"
        ET.SubElement(metadata, "timestamp").text = datetime.now().isoformat()
        ET.SubElement(metadata, "target_url").text = results.get('target_url', '')
        
        # Results
        results_elem = ET.SubElement(root, "results")
        
        for category, items in results.items():
            if isinstance(items, list):
                category_elem = ET.SubElement(results_elem, category)
                for item in items:
                    item_elem = ET.SubElement(category_elem, "item")
                    for key, value in item.items():
                        ET.SubElement(item_elem, key).text = str(value)
        
        # Pretty print XML
        xml_str = ET.tostring(root, encoding='unicode')
        xml_pretty = minidom.parseString(xml_str).toprettyxml(indent="  ")
        
        with open(self.output_file, 'w') as f:
            f.write(xml_pretty)
    
    def _save_markdown(self, results):
        """Save results as Markdown"""
        md_content = f"""# AIBuster Scan Report

## Metadata
- **Target URL:** {results.get('target_url', 'N/A')}
- **Scan Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
- **Duration:** {(datetime.now() - self.scan_start).total_seconds():.1f} seconds

## Summary
| Category | Count |
|----------|-------|
| Found (200) | {len(results.get('found', []))} |
| Redirects | {len(results.get('redirects', []))} |
| Forbidden (403) | {len(results.get('forbidden', []))} |

## Results\n"""
        
        for category, items in results.items():
            if isinstance(items, list) and items:
                md_content += f"\n### {category.title()}\n\n"
                md_content += "| Path | Status | Size | URL |\n"
                md_content += "|------|--------|------|-----|\n"
                
                for item in items:
                    path = item.get('path', '').replace('|', '\\|')
                    url = item.get('url', '').replace('|', '\\|')
                    md_content += f"| `{path}` | {item.get('status', '')} | {item.get('size', 0):,} | {url} |\n"
        
        with open(self.output_file, 'w') as f:
            f.write(md_content)
    
    def _save_text(self, results):
        """Save results as plain text"""
        with open(self.output_file, 'w') as f:
            f.write(f"AIBuster Scan Report\n")
            f.write(f"{'='*50}\n\n")
            f.write(f"Target: {results.get('target_url', '')}\n")
            f.write(f"Date: {datetime.now()}\n\n")
            
            f.write("Results:\n")
            f.write("-"*50 + "\n")
            
            for category, items in results.items():
                if isinstance(items, list) and items:
                    f.write(f"\n{category.upper()}:\n")
                    for item in items:
                        f.write(f"  {item.get('path', '')} - Status: {item.get('status', '')} "
                               f"- Size: {item.get('size', 0):,}\n")

    def generate_report(self, results, format_override=None):
        """Generate comprehensive report"""
        if not self.output_file:
            return
        
        # Determine filename based on format
        format_to_use = format_override or self.format
        base_name = self.output_file.rsplit('.', 1)[0] if '.' in self.output_file else self.output_file
        
        if format_to_use == OutputFormat.JSON:
            filename = f"{base_name}.json"
        elif format_to_use == OutputFormat.CSV:
            filename = f"{base_name}.csv"
        elif format_to_use == OutputFormat.HTML:
            filename = f"{base_name}.html"
        elif format_to_use == OutputFormat.XML:
            filename = f"{base_name}.xml"
        elif format_to_use == OutputFormat.MARKDOWN:
            filename = f"{base_name}.md"
        else:
            filename = f"{base_name}.txt"
        
        # Save with new filename
        original_output = self.output_file
        self.output_file = filename
        self.save_results(results, format_to_use)
        self.output_file = original_output