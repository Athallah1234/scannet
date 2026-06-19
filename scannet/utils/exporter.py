import os
from typing import Dict, Any

def export_report(data: Dict[str, Any], format_type: str, filepath: str) -> bool:
    """Delegates report writing based on export format_type."""
    format_type = format_type.lower()
    
    # Import dynamically to avoid circular dependencies
    if format_type == "json":
        from scannet.report.json_report import JSONReport
        return JSONReport.export(data, filepath)
    elif format_type == "csv":
        from scannet.report.csv_report import CSVReport
        return CSVReport.export(data, filepath)
    elif format_type == "html":
        from scannet.report.html_report import HTMLReport
        return HTMLReport.export(data, filepath)
    elif format_type == "markdown" or format_type == "md":
        from scannet.report.markdown_report import MarkdownReport
        return MarkdownReport.export(data, filepath)
    else:
        raise ValueError(f"Unsupported export format: {format_type}")
