import sys
import json
import os
import html
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class DummyColor:
        def __getattr__(self, name): return ""
    Fore = Style = DummyColor()

def safe_print(text):
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode(sys.stdout.encoding or 'utf-8', errors='replace').decode(sys.stdout.encoding or 'utf-8'))

class Reporter:
    def __init__(self, findings, output_format="console", output_file=None):
        self.findings = findings
        self.format = output_format
        self.output_file = output_file

    def report(self):
        if self.format == "console":
            self._print_console()
        elif self.format == "json":
            self._print_console() # Print brief console summary anyway
            self._write_json()
        elif self.format == "html":
            self._print_console()
            self._write_html()
            
        if self.output_file and self.format == "console":
            self._write_json() # Default fallback to save JSON if file specified with console format
            
    def _get_color(self, severity):
        if severity == "CRITICAL":
            return Fore.RED + Style.BRIGHT
        elif severity == "HIGH":
            return Fore.RED
        elif severity == "MEDIUM":
            return Fore.YELLOW
        else:
            return Fore.CYAN

    def _print_console(self):
        for f in self.findings:
            rule = f['rule']
            sev = rule.get('severity', 'LOW')
            color = self._get_color(sev)
            safe_print(f"{color}[{sev}] {rule['id']}: {rule['name']}{Style.RESET_ALL}")
            safe_print(f"  File: {f['file']}, line {f['line']}")
            safe_print(f"  Code: {f['code']}")
            if 'remediation' in rule:
                safe_print(f"  Fix: {rule['remediation']}")
            safe_print("")
            
        safe_print(f"Scan finished. {len(self.findings)} issues found.")
        if self.output_file:
            safe_print(f"Report saved to {self.output_file}")

    def _write_json(self):
        out_file = self.output_file or "scan_report.json"
        with open(out_file, 'w', encoding='utf-8') as f:
            json.dump(self.findings, f, indent=4)

    def _write_html(self):
        out_file = self.output_file or "scan_report.html"
        html_content = ["<html><head><title>CodeSecureScan Report</title>",
                        "<style>body{font-family: sans-serif; margin: 20px;} .critical{color: red; font-weight: bold;} .high{color: red;} .medium{color: orange;} .low{color: blue;} .finding{border: 1px solid #ccc; padding: 10px; margin-bottom: 10px;}</style>",
                        "</head><body><h1>CodeSecureScan Report</h1>",
                        f"<p>Total findings: {len(self.findings)}</p>"]
        
        for f in self.findings:
            rule = f['rule']
            sev_raw = rule.get('severity', 'LOW')
            sev_class = html.escape(sev_raw.lower())
            sev_display = html.escape(sev_raw)
            r_id = html.escape(rule.get('id', 'Unknown'))
            r_name = html.escape(rule.get('name', 'Unnamed Rule'))
            
            file_name = html.escape(f['file'])
            line_no = html.escape(str(f['line']))
            escaped_code = html.escape(f['code'])
            
            html_content.append(f"<div class='finding'><h3 class='{sev_class}'>[{sev_display}] {r_id}: {r_name}</h3>")
            html_content.append(f"<p><strong>File:</strong> {file_name} (Line {line_no})</p>")
            html_content.append(f"<p><strong>Code:</strong> <code>{escaped_code}</code></p>")
            if 'remediation' in rule:
                remediation = html.escape(rule['remediation'])
                html_content.append(f"<p><strong>Remediation:</strong> {remediation}</p>")
            html_content.append("</div>")
            
        html_content.append("</body></html>")
        with open(out_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(html_content))
