# Export Report Example
import os
from scannet import NetScanner
from scannet.utils.exporter import export_report

def main():
    scanner = NetScanner(
        target="127.0.0.1",
        timeout=1.0,
        authorized=True
    )
    
    print("Scanning localhost...")
    result = scanner.scan_ports([80, 22, 443])
    
    # Export reports
    os.makedirs("output_reports", exist_ok=True)
    
    formats = ["json", "csv", "html", "markdown"]
    for fmt in formats:
        ext = "md" if fmt == "markdown" else fmt
        filepath = f"output_reports/report.{ext}"
        success = export_report(result, fmt, filepath)
        if success:
            print(f"Exported {fmt.upper()} report to: {filepath}")

if __name__ == "__main__":
    main()
