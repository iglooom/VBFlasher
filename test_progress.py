"""Offline terminal checks for the persistent flash footer."""
import contextlib
import fcntl
import io
import os
import pty
import re
import struct
import termios
import time
import unittest
from unittest.mock import patch

from vbf import FlashProgress, download_blocks


def _drain(master):
    """Read whatever the PTY holds right now, without blocking on the slave."""
    out = bytearray()
    os.set_blocking(master, False)
    try:
        while True:
            chunk = os.read(master, 65536)
            if not chunk:
                break
            out.extend(chunk)
    except BlockingIOError:
        pass
    except OSError:
        pass
    finally:
        os.set_blocking(master, True)
    return out.decode(errors="replace")


def _footer_lines(text):
    """Each footer repaint, stripped of SGR codes."""
    return [re.sub(r"\x1b\[[0-9;]*m", "", seg.split("\x1b[K")[0])
            for seg in text.split("\x1b[49m")[1:]]


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
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 6, 64, 0, 0))
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
            self.assertNotIn("\x1b[7m", text)  # no reverse-video white background
            for segment in text.split("\x1b[49m")[1:]:
                bar = re.sub(r"\x1b\[[0-9;]*m", "", segment.split("\x1b[K")[0])
                self.assertEqual(len(bar), 63)
                self.assertRegex(bar, r"^ \d+:\d\d ")  # elapsed clock at left
                # ETA only appears once a transfer stage is running
                self.assertRegex(bar,
                                 r"\[.*\] +\d+\.\d% *(ETA [\d:-]+ )?$")
            self.assertRegex(text, r"\d+\.\d KiB/s \[")
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
            self.assertIn("1.0 KiB/s [", text)
            self.assertIn("-- KiB/s [", text)
            self.assertIn("] 100.0%  ETA 00:00 \x1b[K", text)
            self.assertIn(" 00:01 downloa", text)  # elapsed clock at far left
        finally:
            os.close(master)

    def test_ticker_redraws_clock_without_byte_traffic(self):
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 6, 64, 0, 0))
        try:
            with os.fdopen(slave, "w", buffering=1) as output:
                with patch("sys.stdout", output), patch.dict(os.environ, {"TERM": "xterm"}):
                    bar = FlashProgress(1024, interval=0.1)
                    try:
                        bar.start()
                        bar.stage_name("erase")
                        time.sleep(0.45)  # no advance() at all
                    finally:
                        bar.close()
                    self.assertIsNone(bar._ticker)
            data = bytearray()
            try:
                while True:
                    data.extend(os.read(master, 65536))
            except OSError:
                pass
            text = data.decode()
            # start + stage_name + >=3 ticker repaints of the footer row
            self.assertGreaterEqual(text.count("\x1b[6;1H\x1b[49m"), 5)
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

    def test_eta_hidden_outside_transfer_stages(self):
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 6, 64, 0, 0))
        clock = [10.0]
        try:
            with os.fdopen(slave, "w", buffering=1) as output:
                with (patch("sys.stdout", output),
                      patch.dict(os.environ, {"TERM": "xterm"}),
                      patch("vbf.time.monotonic", side_effect=lambda: clock[0])):
                    bar = FlashProgress(2048, interval=999)
                    try:
                        bar.start()
                        bar.stage_name("erase")
                        clock[0] = 20.0
                        bar.draw(force=True)
                        erase_frames = [s for s in _footer_lines(_drain(master))
                                        if "erase" in s]
                        bar.stage_name("download")
                        clock[0] = 21.0
                        bar.advance(1024)  # 1 KiB/s, 1 KiB left -> ETA 00:01
                        bar.draw(force=True)
                        dl_frames = [s for s in _footer_lines(_drain(master))
                                     if "download" in s]
                    finally:
                        bar.close()
            self.assertTrue(erase_frames)
            for frame in erase_frames:
                self.assertNotIn("ETA", frame)
            self.assertTrue(dl_frames)
            self.assertTrue(any("ETA 00:01" in f for f in dl_frames),
                            dl_frames)
        finally:
            os.close(master)

    def test_summary_reports_elapsed_and_average_speed(self):
        clock = [100.0]
        with patch("vbf.time.monotonic", side_effect=lambda: clock[0]):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                bar = FlashProgress(2048)
                bar.start()
                bar.stage_name("download")
                clock[0] = 102.0
                bar.advance(2048)
                bar.stage_name("finalise")  # banks 2048 B over 2.0 s
                clock[0] = 104.0
                bar.close()
        stats = bar.summary()
        assert stats is not None
        self.assertIn("00:04 (4.0s), 2.0 KiB transferred", stats)
        self.assertIn("0.5 KiB/s overall", stats)
        self.assertIn("1.0 KiB/s during transfers", stats)

    def test_summary_without_start_is_none(self):
        self.assertIsNone(FlashProgress(4).summary())


if __name__ == "__main__":
    unittest.main()
