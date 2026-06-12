import os, re
from core.rule_loader import load_rules
from core.file_handler import get_files

class ScanEngine:
    def __init__(self, rules_dir, min_severity, ignore_dirs):
        self.rules = load_rules(rules_dir)
        self.min_severity = min_severity
        self.ignore_dirs = ignore_dirs.split(',') if ignore_dirs else []

    def scan(self, root_path):
        findings = []
        for filepath in get_files(root_path, self.ignore_dirs):
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            for line_no, line in enumerate(lines, start=1):
                for rule in self.rules:
                    if rule['severity'] < self.min_severity: continue
                    for pattern in rule['patterns']:
                        if self._match(line, pattern):
                            findings.append({
                                'file': filepath,
                                'line': line_no,
                                'code': line.strip(),
                                'rule': rule
                            })
        return findings

    def _match(self, line, pattern):
        if 'regex' in pattern:
            return re.search(pattern['regex'], line)
        if 'keywords' in pattern:
            return any(kw in line for kw in pattern['keywords'])
        return False