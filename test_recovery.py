"""Offline tests for the power-up PBL recovery window."""
import contextlib
import errno
import io
import socket
import unittest
from unittest.mock import Mock, patch

import vbflasher


GWM_SBL = "sbl/CM5T-14F532-AA.vbf"


class RecoveryTests(unittest.TestCase):
    def parse(self, *options):
        args = vbflasher.build_parser().parse_args(["flash", *options])
        args.execute = not args.dry_run
        return args

    def test_recovery_ignores_custom_app_programming_reply(self):
        args = self.parse("GWM", "--recovery", "--hw", "DG9T-14F536-BA")
        ecu = Mock()
        ecu.txid = 0x716
        ecu.req.side_effect = [bytes.fromhex("5002003201F4"),
                               bytes.fromhex("5002001901F4")]
        with patch.object(vbflasher.time, "sleep"), contextlib.redirect_stdout(io.StringIO()):
            vbflasher.enter_programming_session(ecu, args)
        self.assertEqual(ecu.req.call_count, 2)

    def test_recovery_retries_without_wake_or_identity_until_session(self):
        args = self.parse("GWM", "--recovery", "--hw", "KNOWN")
        ecu = Mock()
        ecu.req.side_effect = [None, b"\x7f\x10\x21", b"\x50\x01", b"\x50\x02"]
        with patch.object(vbflasher.time, "sleep"), contextlib.redirect_stdout(io.StringIO()):
            vbflasher.enter_programming_session(ecu, args)
        self.assertEqual(ecu.req.call_count, 4)
        ecu.wake.assert_not_called()
        ecu.read_did.assert_not_called()
        for call in ecu.req.call_args_list:
            self.assertEqual(call.args, ("1002",))
            self.assertEqual(call.kwargs["timeout"], 0.2)
            self.assertEqual(call.kwargs["busy_retries"], 0)

    def test_recovery_survives_socket_send_timeout(self):
        args = self.parse("GWM", "--recovery", "--hw", "KNOWN")

        class BootingSocket:
            def __init__(self):
                self.attempts = 0

            def send(self, data):
                self.attempts += 1
                if self.attempts == 2:
                    raise OSError(errno.ETIMEDOUT, "Connection timed out")

            def settimeout(self, value):
                pass

            def recv(self, length):
                if self.attempts == 1:
                    raise socket.timeout("timed out")
                return bytes.fromhex("5002001901F4")

        ecu = vbflasher.Ecu("can0", 0x716, 0x71E, execute=False)
        ecu.execute = True
        boot = BootingSocket()
        with (patch.object(ecu, "s", boot), patch.object(vbflasher.time, "sleep"),
              contextlib.redirect_stdout(io.StringIO())):
            vbflasher.enter_programming_session(ecu, args)
        self.assertEqual(boot.attempts, 3)
        self.assertEqual(ecu.sent, ["1002"] * 3)

    def test_gwm_custom_sbl_ack_is_not_accepted_as_running_sbl(self):
        args = self.parse(GWM_SBL, "--recovery", "--hw", "DG9T-14F536-BA",
                          "--test-sbl", "--yes", "--logfile", "",
                          "--tp-interval", "0")
        ecu = Mock()
        ecu.expect.side_effect = [bytes.fromhex("6701000000"),
                                  bytes.fromhex("71010301")]
        with (patch.object(vbflasher, "iface_is_up", return_value=True),
              patch.object(vbflasher, "Ecu", return_value=ecu),
              patch.object(vbflasher, "enter_programming_session"),
              patch.object(vbflasher, "download_blocks"),
              contextlib.redirect_stdout(io.StringIO())):
            with self.assertRaisesRegex(SystemExit, "PBL.*power-cycle"):
                vbflasher.do_flash(args)
        ecu.req.assert_not_called()

    def test_gwm_pbl_sbl_ack_allows_sbl_only_rehearsal(self):
        args = self.parse(GWM_SBL, "--recovery", "--hw", "DG9T-14F536-BA",
                          "--test-sbl", "--yes", "--logfile", "",
                          "--tp-interval", "0")
        ecu = Mock()
        ecu.expect.side_effect = [bytes.fromhex("6701000000"),
                                  bytes.fromhex("7101030110")]
        out = io.StringIO()
        with (patch.object(vbflasher, "iface_is_up", return_value=True),
              patch.object(vbflasher, "Ecu", return_value=ecu),
              patch.object(vbflasher, "enter_programming_session"),
              patch.object(vbflasher, "download_blocks"),
              contextlib.redirect_stdout(out)):
            vbflasher.do_flash(args)
        self.assertIn("SBL running", out.getvalue())
        ecu.req.assert_called_once_with("1101", timeout=8.0,
                                        what="11 01 ECUReset")

    def test_recovery_does_not_hide_other_transport_errors(self):
        args = self.parse("GWM", "--recovery", "--hw", "KNOWN")
        ecu = Mock()
        ecu.req.side_effect = OSError(errno.ENETDOWN, "Network is down")
        with self.assertRaises(OSError) as raised:
            vbflasher.enter_programming_session(ecu, args)
        self.assertEqual(raised.exception.errno, errno.ENETDOWN)
        self.assertEqual(ecu.req.call_count, 1)

    def test_recovery_can_be_interrupted(self):
        args = self.parse("GWM", "--recovery", "--hw", "KNOWN")
        ecu = Mock()
        ecu.req.side_effect = [None, None, KeyboardInterrupt]
        with patch.object(vbflasher.time, "sleep"), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                vbflasher.enter_programming_session(ecu, args)
        self.assertEqual(ecu.req.call_count, 3)

    def test_normal_flash_stays_bounded(self):
        args = self.parse("GWM", "--wake-tries", "2")
        ecu = Mock()
        ecu.req.return_value = None
        with patch.object(vbflasher.time, "sleep"):
            with self.assertRaisesRegex(SystemExit, "after 2 tries"):
                vbflasher.enter_programming_session(ecu, args)
        self.assertEqual(ecu.req.call_count, 2)

    def test_recovery_requires_offline_identity_or_explicit_files(self):
        for argv in ((GWM_SBL, "--recovery"),
                     (GWM_SBL, "--recovery", "--sbl", GWM_SBL)):
            args = self.parse(*argv)
            with patch.object(vbflasher, "flash_session") as session:
                with self.assertRaisesRegex(SystemExit, "--hw"):
                    vbflasher.do_flash(args)
                session.assert_not_called()

    def test_recovery_skips_identity_before_first_session(self):
        args = self.parse(GWM_SBL, "--recovery", "--hw", "KNOWN",
                          "--test-sbl", "--yes", "--logfile", "",
                          "--tp-interval", "0")
        ecu = Mock()
        out = io.StringIO()
        with (patch.object(vbflasher, "iface_is_up", return_value=True),
              patch.object(vbflasher, "Ecu", return_value=ecu),
              patch.object(vbflasher, "read_identity") as ident,
              patch.object(vbflasher, "enter_programming_session",
                           side_effect=RuntimeError("reached first 10 02")) as session,
              contextlib.redirect_stdout(out)):
            with self.assertRaisesRegex(RuntimeError, "reached first 10 02"):
                vbflasher.do_flash(args)
        ident.assert_not_called()
        ecu.wake.assert_not_called()
        ecu.read_did.assert_not_called()
        session.assert_called_once()
        self.assertIn("--recovery", out.getvalue())

    def test_recovery_dry_run_opens_no_socket(self):
        args = self.parse(GWM_SBL, "--recovery", "--test-sbl", "--dry-run",
                          "--logfile", "")
        with patch.object(vbflasher, "Ecu") as ecu, contextlib.redirect_stdout(io.StringIO()):
            vbflasher.do_flash(args)
        self.assertFalse(ecu.call_args.kwargs["execute"])


if __name__ == "__main__":
    unittest.main()
