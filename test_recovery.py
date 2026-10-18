"""Offline tests for the power-up PBL recovery window.

The catch strategy is FORScan's, taken from the ABS captures: a continuous
functional 10 82 flood (vbf.PblFlood) with 22 D100 / 10 02 probes on the side.
"""
import contextlib
import errno
import io
import socket
import struct
import unittest
from unittest.mock import Mock, patch

import vbflasher


GWM_SBL = "sbl/CM5T-14F532-AA.vbf"
PBL_50_02 = bytes.fromhex("5002001901F4")


class FakeFlood:
    """Stands in for vbf.PblFlood: records that it ran, touches no socket."""
    instances = []

    def __init__(self, iface, can_id=0x7DF, interval=0.012, execute=True,
                 log=None, payload=(0x10, 0x82)):
        self.iface, self.can_id, self.interval = iface, can_id, interval
        self.execute, self.log, self.payload = execute, log, payload
        self.sent = 0
        self.started = self.stopped = 0
        FakeFlood.instances.append(self)

    def start(self):
        self.started += 1
        return self

    def stop(self):
        self.stopped += 1


@contextlib.contextmanager
def flood_patched():
    FakeFlood.instances = []
    with (patch.object(vbflasher, "PblFlood", FakeFlood),
          patch.object(vbflasher.time, "sleep"),
          contextlib.redirect_stdout(io.StringIO())):
        yield FakeFlood.instances


class RecoveryTests(unittest.TestCase):
    def parse(self, *options):
        args = vbflasher.build_parser().parse_args(["flash", *options])
        args.execute = not args.dry_run
        return args

    # --- the catch ------------------------------------------------------
    def test_catch_floods_functional_10_82_at_forscan_rate(self):
        args = self.parse("GWM", "--recovery", "--hw", "KNOWN")
        ecu = Mock()
        ecu.txid = 0x716
        ecu.iface = "can0"
        # round 1: D100 silent, 10 02 silent. round 2: D100 says bootloader.
        ecu.req.side_effect = [None, None, bytes.fromhex("62D10002")]
        with flood_patched() as floods:
            caught = vbflasher.recovery_catch_pbl(ecu, args)
        self.assertEqual(caught, "D100=02")
        self.assertEqual(len(floods), 1)
        flood = floods[0]
        self.assertEqual((flood.can_id, flood.interval), (0x7DF, 0.012))
        self.assertEqual(flood.payload, (0x10, 0x82))
        self.assertEqual((flood.started, flood.stopped), (1, 1))

    def test_d100_negative_response_does_not_stop_the_catch(self):
        """An NRC on D100 proves nothing: keep flooding, then accept the PBL."""
        args = self.parse("GWM", "--recovery", "--hw", "KNOWN")
        ecu = Mock()
        ecu.txid = 0x716
        ecu.iface = "can0"
        ecu.req.side_effect = [
            bytes.fromhex("7F2231"),   # D100 requestOutOfRange
            None,                      # 10 02 unanswered
            bytes.fromhex("7F2211"),   # D100 serviceNotSupported
            PBL_50_02,                 # 10 02 -> the known PBL reply
        ]
        with flood_patched():
            caught = vbflasher.recovery_catch_pbl(ecu, args)
        self.assertEqual(caught, "10 02")
        self.assertEqual(ecu.req.call_count, 4)

    def test_catch_accepts_any_50_02_without_fingerprint_checks(self):
        """Catching the PBL is the only job; the flash flow checks the rest."""
        args = self.parse("GWM", "--recovery", "--hw", "DG9T-14F536-BA")
        ecu = Mock()
        ecu.txid = 0x716
        ecu.iface = "can0"
        ecu.req.side_effect = [None, bytes.fromhex("5002003201F4")]
        with flood_patched():
            caught = vbflasher.recovery_catch_pbl(ecu, args)
        self.assertEqual(caught, "10 02")
        self.assertEqual(ecu.req.call_count, 2)

    def test_catch_never_wakes_or_reads_identity(self):
        args = self.parse("GWM", "--recovery", "--hw", "KNOWN")
        ecu = Mock()
        ecu.txid = 0x716
        ecu.iface = "can0"
        ecu.req.side_effect = [None, None, bytes.fromhex("62D10002")]
        with flood_patched():
            vbflasher.recovery_catch_pbl(ecu, args)
        ecu.wake.assert_not_called()
        ecu.read_did.assert_not_called()
        for call in ecu.req.call_args_list:
            self.assertIn(call.args[0], ("22D100", "1002"))
            self.assertEqual(call.kwargs["busy_retries"], 0)
            self.assertEqual(call.kwargs["timeout"], 0.2)

    def test_catch_survives_socket_send_timeout(self):
        """ISO-TP send() times out while the ECU is unpowered; keep probing."""
        args = self.parse("GWM", "--recovery", "--hw", "KNOWN")

        class BootingSocket:
            """D100 stays silent; the 2nd send times out (module unpowered);
            the 2nd 10 02 is answered by the woken bootloader."""
            def __init__(self):
                self.attempts = 0
                self.last = b""

            def send(self, data):
                self.attempts += 1
                self.last = data
                if self.attempts == 2:
                    raise OSError(errno.ETIMEDOUT, "Connection timed out")

            def settimeout(self, value):
                pass

            def recv(self, length):
                if self.last == bytes.fromhex("1002") and self.attempts >= 4:
                    return PBL_50_02
                raise socket.timeout("timed out")

        ecu = vbflasher.Ecu("can0", 0x716, 0x71E, execute=False)
        ecu.execute = True
        boot = BootingSocket()
        with patch.object(ecu, "s", boot), flood_patched():
            caught = vbflasher.recovery_catch_pbl(ecu, args)
        self.assertEqual(caught, "10 02")
        self.assertEqual(ecu.sent, ["22D100", "1002", "22D100", "1002"])

    def test_catch_does_not_hide_other_transport_errors(self):
        args = self.parse("GWM", "--recovery", "--hw", "KNOWN")
        ecu = Mock()
        ecu.txid = 0x716
        ecu.iface = "can0"
        ecu.req.side_effect = OSError(errno.ENETDOWN, "Network is down")
        with flood_patched() as floods:
            with self.assertRaises(OSError) as raised:
                vbflasher.recovery_catch_pbl(ecu, args)
        self.assertEqual(raised.exception.errno, errno.ENETDOWN)
        self.assertEqual(ecu.req.call_count, 1)
        self.assertEqual(floods[0].stopped, 1)   # flood always torn down

    def test_catch_can_be_interrupted(self):
        args = self.parse("GWM", "--recovery", "--hw", "KNOWN")
        ecu = Mock()
        ecu.txid = 0x716
        ecu.iface = "can0"
        ecu.req.side_effect = [None, None, KeyboardInterrupt]
        with flood_patched() as floods:
            with self.assertRaises(KeyboardInterrupt):
                vbflasher.recovery_catch_pbl(ecu, args)
        self.assertEqual(ecu.req.call_count, 3)
        self.assertEqual(floods[0].stopped, 1)

    def test_flood_can_be_disabled_for_a_pure_probe_catch(self):
        args = self.parse("GWM", "--recovery", "--hw", "KNOWN",
                          "--flood-interval", "0")
        ecu = Mock()
        ecu.txid = 0x716
        ecu.iface = "can0"
        ecu.req.side_effect = [bytes.fromhex("62D10002")]
        with flood_patched() as floods:
            vbflasher.recovery_catch_pbl(ecu, args)
        self.assertEqual(floods[0].interval, 0.0)

    # --- session hand-off ------------------------------------------------
    def test_session_is_confirmed_physically_after_the_catch(self):
        args = self.parse("GWM", "--recovery", "--hw", "KNOWN")
        ecu = Mock()
        ecu.req.side_effect = [None, PBL_50_02]
        with (patch.object(vbflasher, "recovery_catch_pbl") as catch,
              patch.object(vbflasher.time, "sleep"),
              contextlib.redirect_stdout(io.StringIO())):
            vbflasher.enter_programming_session(ecu, args)
        catch.assert_called_once()
        self.assertEqual([c.args[0] for c in ecu.req.call_args_list],
                         ["1002", "1002"])

    def test_lost_window_after_catch_is_reported(self):
        args = self.parse("GWM", "--recovery", "--hw", "KNOWN",
                          "--wake-tries", "2")
        ecu = Mock()
        ecu.req.return_value = None
        with (patch.object(vbflasher, "recovery_catch_pbl"),
              patch.object(vbflasher.time, "sleep"),
              contextlib.redirect_stdout(io.StringIO())):
            with self.assertRaisesRegex(SystemExit, "window closed"):
                vbflasher.enter_programming_session(ecu, args)

    def test_normal_flash_stays_bounded_and_never_floods(self):
        args = self.parse("GWM", "--wake-tries", "2")
        ecu = Mock()
        ecu.req.return_value = None
        with (patch.object(vbflasher, "PblFlood", FakeFlood),
              patch.object(vbflasher.time, "sleep")):
            with self.assertRaisesRegex(SystemExit, "after 2 tries"):
                vbflasher.enter_programming_session(ecu, args)
        self.assertEqual(ecu.req.call_count, 2)
        self.assertEqual(ecu.req.call_args.kwargs["timeout"], 1.0)

    # --- flash_session integration --------------------------------------
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
              patch.object(vbflasher, "BusQuiet"),
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
              patch.object(vbflasher, "BusQuiet"),
              patch.object(vbflasher, "download_blocks"),
              contextlib.redirect_stdout(out)):
            vbflasher.do_flash(args)
        self.assertIn("SBL running", out.getvalue())
        ecu.req.assert_called_once_with("1101", timeout=8.0,
                                        what="11 01 ECUReset")

    def test_recovery_forces_quiet_bus(self):
        args = self.parse(GWM_SBL, "--recovery", "--hw", "KNOWN",
                          "--test-sbl", "--yes", "--logfile", "")
        self.assertFalse(args.quiet_bus)
        with (patch.object(vbflasher, "flash_session"),
              contextlib.redirect_stdout(io.StringIO())):
            vbflasher.do_flash(args)
        self.assertTrue(args.quiet_bus)

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
              patch.object(vbflasher, "BusQuiet"),
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


class PblFloodTests(unittest.TestCase):
    def test_dry_run_flood_opens_no_socket_and_sends_nothing(self):
        flood = vbflasher.PblFlood("can0", execute=False)
        with flood:
            pass
        self.assertEqual(flood.sent, 0)

    def test_zero_interval_disables_the_flood(self):
        flood = vbflasher.PblFlood("can0", interval=0, execute=True)
        with flood:
            pass
        self.assertEqual(flood.sent, 0)

    def test_frame_bytes_match_the_forscan_capture(self):
        """The flood must be byte-identical to 7DF#0210820000000000."""
        import vbf
        frame = vbf._frame(0x7DF, vbf._single((0x10, 0x82)))
        can_id, dlc, data = struct.unpack("=IB3x8s", frame)
        self.assertEqual(can_id, 0x7DF)
        self.assertEqual(dlc, 8)
        self.assertEqual(data.hex().upper(), "0210820000000000")

    def test_log_gets_one_summary_line_not_one_per_frame(self):
        log = io.StringIO()
        log.flush = lambda: None
        flood = vbflasher.PblFlood("can0", execute=False, log=log)
        flood.sent = 500
        flood.stop()
        lines = log.getvalue().strip().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertIn("x500", lines[0])
        self.assertIn("7DF#1082", lines[0])


if __name__ == "__main__":
    unittest.main()
