import json
from typing import Dict, Any

class JSONReport:
    @staticmethod
    def export(data: Dict[str, Any], filepath: str) -> bool:
        """Saves scan data in structured JSON format."""
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
            return True
        except Exception:
            return False
