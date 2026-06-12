import os
import re
from core.rule_loader import load_rules
from core.file_handler import get_files
from utils.regex_helper import RegexHelper

SEVERITY_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB to prevent OOM when reading full text

class ScanEngine:
    def __init__(self, rules_dir, min_severity, ignore_dirs):
        self.rules = load_rules(rules_dir)
        self.min_severity = min_severity if isinstance(min_severity, int) else SEVERITY_LEVELS.get(min_severity, 1)
        self.ignore_dirs = ignore_dirs.split(',') if ignore_dirs else []

    def scan(self, root_path):
        findings = []
        for filepath in get_files(root_path, self.ignore_dirs):
            try:
                # OOM protection: skip massive files
                if os.path.getsize(filepath) > MAX_FILE_SIZE:
                    continue
                    
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content_lines = f.readlines()
                    
                for rule in self.rules:
                    rule_severity_str = rule.get('severity', 'LOW')
                    rule_severity_val = SEVERITY_LEVELS.get(rule_severity_str, 1)
                    if rule_severity_val < self.min_severity: 
                        continue

                    # If rule specifies multiline, process it differently
                    if rule.get('multiline'):
                        findings.extend(self.scan_multiline(filepath, content_lines, rule))
                        continue

                    for line_no_zero, line in enumerate(content_lines):
                        line_no = line_no_zero + 1
                        for pattern in rule.get('patterns', []):
                            if self._match(line, pattern):
                                
                                # Contextual decorator check (e.g. require_decorator: "@login_required")
                                required_dec = rule.get('require_decorator')
                                if required_dec and self.check_decorator(content_lines, line_no_zero, required_dec):
                                    continue # Safe, it has the decorator
                                    
                                # Check ignore_if_regex
                                if 'ignore_if_regex' in rule:
                                    regex_obj = RegexHelper.compile(rule['ignore_if_regex'])
                                    if regex_obj.search(line):
                                        continue
                                
                                findings.append({
                                    'file': filepath,
                                    'line': line_no,
                                    'code': line.strip()[:100],
                                    'rule': rule
                                })
            except Exception:
                continue
        return findings

    def scan_multiline(self, filepath, content_lines, rule):
        findings = []
        full_text = "".join(content_lines)
        for pattern in rule.get('patterns', []):
            if 'regex' in pattern:
                regex_obj = re.compile(pattern['regex'], re.IGNORECASE | re.DOTALL)
                for match in regex_obj.finditer(full_text):
                    line_no = full_text[:match.start()].count('\n') + 1
                    
                    if 'ignore_if_regex' in rule:
                        ignore_regex = RegexHelper.compile(rule['ignore_if_regex'])
                        if ignore_regex.search(match.group(0)):
                            continue
                            
                    findings.append({
                        'file': filepath,
                        'line': line_no,
                        'code': match.group(0).replace('\n', ' ').strip()[:100],
                        'rule': rule
                    })
        return findings

    def check_decorator(self, lines, current_idx, decorator_name):
        # Look 5 lines above the function definition
        for i in range(max(0, current_idx - 5), current_idx):
            if decorator_name in lines[i]:
                return True
        return False

    def _match(self, line, pattern):
        if 'regex' in pattern:
            regex_obj = RegexHelper.compile(pattern['regex'])
            return bool(regex_obj.search(line))
        if 'keywords' in pattern:
            return any(kw in line for kw in pattern['keywords'])
        return False