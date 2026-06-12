import argparse
import sys
from core.engine import ScanEngine
from core.reporter import Reporter

def main():
    parser = argparse.ArgumentParser(description="CodeSecureScan - Offline Local Code Security Scanner")
    parser.add_argument("path", help="Root directory or file to scan")
    parser.add_argument("--rules-dir", default="./rules", help="Path to rules directory")
    parser.add_argument("--output", help="Save report to file")
    parser.add_argument("--format", choices=["console", "json", "html"], default="console", help="Output format")
    parser.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default="LOW", help="Minimum severity to report")
    parser.add_argument("--ignore-dirs", help="Comma separated directories to skip")
    args = parser.parse_args()
    
    severity_levels = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    min_severity_val = severity_levels.get(args.severity, 1)

    try:
        engine = ScanEngine(args.rules_dir, min_severity_val, args.ignore_dirs)
        print(f"[*] Starting CodeSecureScan on {args.path} ...")
        findings = engine.scan(args.path)
        
        reporter = Reporter(findings, args.format, args.output)
        reporter.report()
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
