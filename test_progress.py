"""Offline terminal checks for the persistent flash footer."""
import contextlib
import fcntl
import io
import os
import pty
import re
import struct
import termios
import unittest
from unittest.mock import patch

from vbf import FlashProgress, download_blocks


class FakeEcu:
    execute = True

    def expect(self, request, sid, label, **kwargs):
        print(f"   OK {label}")
        if sid == 0x74:
            return bytes.fromhex("741006")  # 4 payload bytes per transfer
        return bytes.fromhex("7700")

    def req(self, request, **kwargs):
        return bytes.fromhex("7601")


class ProgressTests(unittest.TestCase):
    def test_footer_survives_block_logs_and_uses_terminal_width(self):
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 6, 40, 0, 0))
        try:
            with os.fdopen(slave, "w", buffering=1) as output:
                with patch("sys.stdout", output), patch.dict(os.environ, {"TERM": "xterm"}):
                    bar = FlashProgress(8, interval=999)
                    try:
                        bar.start()
                        bar.stage_name("download")
                        blocks = [{"start": 0x1000, "length": 4, "data": b"abcd"},
                                  {"start": 0x2000, "length": 4, "data": b"efgh"}]
                        download_blocks(FakeEcu(), blocks, "test", progress=bar)
                    finally:
                        bar.close()
            data = bytearray()
            try:
                while True:
                    data.extend(os.read(master, 65536))
            except OSError:  # PTY EOF after slave closes
                pass
            text = data.decode()
            self.assertIn("\x1b[1;5r", text)
            self.assertIn("\x1b[6;1H", text)
            self.assertIn("50.0%", text)
            self.assertIn("100.0%", text)
            self.assertIn("blk1 37 TransferExit", text)
            self.assertIn("\x1b[r", text)  # margins restored
            self.assertIn("\x1b[49m", text)  # terminal's normal background
            self.assertIn("\x1b[97m█", text)  # white filled bar
            self.assertRegex(text, r"\]\s+\d+\.\d KiB/s \x1b\[K")
            self.assertNotIn("\x1b[7m", text)  # no reverse-video white background
            for segment in text.split("\x1b[49m")[1:]:
                bar = segment.split("\x1b[K")[0]
                self.assertEqual(len(re.sub(r"\x1b\[[0-9;]*m", "", bar)), 39)
        finally:
            os.close(master)

    def test_speed_uses_current_transfer_stage(self):
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 6, 48, 0, 0))
        clock = [10.0]
        try:
            with os.fdopen(slave, "w", buffering=1) as output:
                with (patch("sys.stdout", output),
                      patch.dict(os.environ, {"TERM": "xterm"}),
                      patch("vbf.time.monotonic", side_effect=lambda: clock[0])):
                    bar = FlashProgress(1024, interval=999)
                    try:
                        bar.start()
                        bar.stage_name("download")
                        clock[0] = 11.0
                        download_blocks(FakeEcu(), [{"start": 0x1000,
                                                     "length": 1024,
                                                     "data": bytes(1024)}],
                                        "test", progress=bar)
                        bar.stage_name("erase")
                    finally:
                        bar.close()
            data = bytearray()
            try:
                while True:
                    data.extend(os.read(master, 65536))
            except OSError:
                pass
            text = data.decode()
            self.assertIn("] 1.0 KiB/s \x1b[K", text)
            self.assertIn("] -- KiB/s \x1b[K", text)
        finally:
            os.close(master)

    def test_redirected_output_has_no_terminal_controls(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            bar = FlashProgress(4)
            bar.start()
            bar.advance(4)
            bar.close()
        self.assertFalse(bar.enabled)
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
