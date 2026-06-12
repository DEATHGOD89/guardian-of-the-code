import os
from core.rule_loader import load_rules
from core.file_handler import get_files
from utils.regex_helper import RegexHelper

SEVERITY_LEVELS = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

class ScanEngine:
    def __init__(self, rules_dir, min_severity, ignore_dirs):
        self.rules = load_rules(rules_dir)
        self.min_severity = min_severity if isinstance(min_severity, int) else SEVERITY_LEVELS.get(min_severity, 1)
        self.ignore_dirs = ignore_dirs.split(',') if ignore_dirs else []

    def scan(self, root_path):
        findings = []
        for filepath in get_files(root_path, self.ignore_dirs):
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    for line_no, line in enumerate(f, start=1):
                        for rule in self.rules:
                            rule_severity_str = rule.get('severity', 'LOW')
                            rule_severity_val = SEVERITY_LEVELS.get(rule_severity_str, 1)
                            if rule_severity_val < self.min_severity: 
                                continue
                            
                            for pattern in rule.get('patterns', []):
                                if self._match(line, pattern):
                                    # Check ignore_if_regex
                                    if 'ignore_if_regex' in rule:
                                        regex_obj = RegexHelper.compile(rule['ignore_if_regex'])
                                        if regex_obj.search(line):
                                            continue
                                    
                                    findings.append({
                                        'file': filepath,
                                        'line': line_no,
                                        'code': line.strip(),
                                        'rule': rule
                                    })
            except Exception:
                # Ignore files that cannot be read
                continue
        return findings

    def _match(self, line, pattern):
        if 'regex' in pattern:
            regex_obj = RegexHelper.compile(pattern['regex'])
            return bool(regex_obj.search(line))
        if 'keywords' in pattern:
            return any(kw in line for kw in pattern['keywords'])
        return False