import unittest
import os
import tempfile
import json
from scannet.utils.exporter import export_report

class TestExporter(unittest.TestCase):
    def setUp(self):
        self.dummy_data = {
            "target": "127.0.0.1",
            "resolved_ip": "127.0.0.1",
            "hosts": {
                "127.0.0.1": {
                    "hostname": "localhost",
                    "os_estimation": "Linux/Unix (Estimated, score=3)",
                    "ports": {
                        80: {"state": "open", "service": "http", "banner": "Apache/2.4.41"}
                    }
                }
            },
            "summary": {
                "scan_duration": 1.25,
                "active_hosts": 1,
                "open_ports": 1
            }
        }
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_export_json(self):
        filepath = os.path.join(self.temp_dir.name, "report.json")
        success = export_report(self.dummy_data, "json", filepath)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(filepath))
        
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.assertEqual(data["target"], "127.0.0.1")

    def test_export_csv(self):
        filepath = os.path.join(self.temp_dir.name, "report.csv")
        success = export_report(self.dummy_data, "csv", filepath)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(filepath))

    def test_export_html(self):
        filepath = os.path.join(self.temp_dir.name, "report.html")
        success = export_report(self.dummy_data, "html", filepath)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(filepath))

    def test_export_markdown(self):
        filepath = os.path.join(self.temp_dir.name, "report.md")
        success = export_report(self.dummy_data, "markdown", filepath)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(filepath))

if __name__ == "__main__":
    unittest.main()
