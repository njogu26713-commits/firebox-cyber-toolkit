import struct
import tempfile
import unittest
from pathlib import Path

from firebox.modules import wifi


class WifiTests(unittest.TestCase):
    def test_status_does_not_scan(self):
        result = wifi.status()
        self.assertFalse(result["scan_performed"])
        self.assertEqual(result["scope"], "local interface inventory only")

    def test_pcap_metadata_does_not_decode_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.pcap"
            global_header = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 105)
            packet_header = struct.pack("<IIII", 1, 2, 4, 4)
            path.write_bytes(global_header + packet_header + b"test")
            result = wifi.pcap_metadata(str(path))
            self.assertEqual(result["packet_count"], 1)
            self.assertEqual(result["captured_bytes"], 4)
            self.assertFalse(result["payloads_decoded"])

    def test_invalid_interface_rejected(self):
        with self.assertRaises(ValueError):
            wifi.audit("../../wlan0")


if __name__ == "__main__":
    unittest.main()
