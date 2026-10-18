"""Offline coverage for selecting an ECU without an application VBF."""
import contextlib
import io
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import ecu_db
import vbflasher
from vbf import Vbf, lzss_encode


class FlashCliTests(unittest.TestCase):
    def test_security_is_enabled_by_default(self):
        args = vbflasher.build_parser().parse_args(["flash", "APP.vbf"])
        self.assertFalse(args.skip_security)

    def test_recovery_skip_security_needs_sbl_but_not_secret(self):
        args = vbflasher.build_parser().parse_args(
            ["flash", "APIM", "--test-sbl", "--recovery", "--skip-security",
             "--sbl", "sbl/CM5T-14F532-AA.vbf"])
        args.execute = True
        with (patch.object(vbflasher, "flash_session") as session,
              contextlib.redirect_stdout(io.StringIO())):
            vbflasher.do_flash(args)
        session.assert_called_once_with(0x7D0, [], args)
        args.sbl = None
        with patch.object(vbflasher, "flash_session") as session:
            with self.assertRaisesRegex(SystemExit, "--hw"):
                vbflasher.do_flash(args)
        session.assert_not_called()

    def test_skip_security_enters_programming_and_loads_sbl_without_secret(self):
        args = vbflasher.build_parser().parse_args(
            ["flash", "APIM", "--test-sbl", "--skip-security", "--yes",
             "--sbl", "sbl/CM5T-14F532-AA.vbf", "--logfile", "",
             "--tp-interval", "0"])
        args.execute = True
        ecu = Mock()
        out = io.StringIO()
        with (patch.object(vbflasher, "iface_is_up", return_value=True),
              patch.object(vbflasher, "Ecu", return_value=ecu),
              patch.object(vbflasher, "read_identity", return_value={}),
              patch.object(ecu_db.EcuProfile, "pick_secret",
                           side_effect=AssertionError("must not resolve a secret")),
              patch.object(vbflasher, "enter_programming_session") as session,
              patch.object(vbflasher, "BusQuiet"),
              patch.object(vbflasher, "Keepalive"),
              patch.object(vbflasher, "time"),
              patch.object(vbflasher, "download_blocks") as download,
              contextlib.redirect_stdout(out)):
            vbflasher.do_flash(args)
        session.assert_called_once_with(ecu, args)
        download.assert_called_once()
        requests = [c.args[0] for c in ecu.expect.call_args_list]
        self.assertTrue(any(r.startswith("31010301") for r in requests))
        self.assertFalse(any(r.startswith("27") for r in requests))
        self.assertIn("SKIPPED (--skip-security)", out.getvalue())
        self.assertNotIn("   unlocked", out.getvalue())

    def test_ipma_reads_software_dids_for_family_gate(self):
        profile = ecu_db.get_profile(0x706)
        values = {"F188": "F1FT-14F397-AA", "F120": "F1FT-14F397-AB",
                  "F124": "F1FT-14F398-AF", "F125": "F1FT-14F398-AG"}
        ecu = Mock()
        ecu.read_did.side_effect = lambda did: values.get(did)
        ecu.last_did_status = None
        with contextlib.redirect_stdout(io.StringIO()):
            ident = vbflasher.read_identity(ecu, profile)
        for did in ("F120", "F124", "F125"):
            self.assertEqual(ident.get(did), values[did])
            vbf = Mock(part=values[did], ptype="DATA")
            self.assertEqual(vbflasher.resolve_gate_did(vbf, ident, profile),
                             (did, values[did], "exact"))
        vbf = Mock(part="F1FT-14F398-AH", ptype="DATA")
        self.assertEqual(vbflasher.resolve_gate_did(vbf, ident, profile)[2],
                         "family")

    def test_ecu_selector_requires_test_sbl(self):
        args = vbflasher.build_parser().parse_args(["flash", "GWM", "--test-sbl"])
        args.execute = False
        with patch.object(vbflasher, "flash_session") as session:
            vbflasher.do_flash(args)
        session.assert_called_once_with(0x716, [], args)

        args = vbflasher.build_parser().parse_args(["flash", "GWM"])
        args.execute = False
        with self.assertRaisesRegex(SystemExit, "GWM: not found"):
            vbflasher.do_flash(args)

    def test_missing_target_refused_without_bus(self):
        for argv in (["flash", "--test-sbl"], ["flash"]):
            args = vbflasher.build_parser().parse_args(argv)
            args.execute = False
            with self.assertRaisesRegex(SystemExit, "requires VBF file"):
                vbflasher.do_flash(args)

    def test_sbl_only_dry_run_has_no_flash_plan(self):
        args = vbflasher.build_parser().parse_args(
            ["flash", "GWM", "--test-sbl", "--dry-run", "--logfile", ""])
        args.execute = False
        out = io.StringIO()
        with contextlib.redirect_stdout(out), patch.object(vbflasher, "Ecu") as ecu:
            vbflasher.do_flash(args)
        ecu.assert_called_once_with("can0", 0x716, 0x71E, execute=False,
                                    logfile=None)
        text = out.getvalue()
        self.assertIn("MODE         --test-sbl", text)
        self.assertIn("NO erase, NO write", text)
        self.assertNotIn("   FLASH  ", text)
        self.assertNotIn("      ERASE ", text)

    def test_explicit_sbl_override_dry_run(self):
        args = vbflasher.build_parser().parse_args(
            ["flash", "GWM", "--test-sbl", "--dry-run", "--logfile", "",
             "--sbl", "sbl/CM5T-14F532-AA.vbf"])
        args.execute = False
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            vbflasher.do_flash(args)
        self.assertIn("explicit --sbl", out.getvalue())

    def test_blank_skip_rejects_non_erased_fill(self):
        image = Vbf.__new__(Vbf)
        image.path = "<synthetic>"
        image.dfi = None
        image.omit = []
        image.erase = [(0x1000, 0x2200)]
        data = b"\xAA" * 0x100 + b"\x00" * 0x2000 + b"\xBB" * 0x100
        image.blocks = [dict(start=0x1000, length=len(data), data=data, crc=0)]
        image._unpacked = {}
        with self.assertRaisesRegex(ValueError, "0xFF"):
            image.flash_blocks(skip_blank=0x1000, blank_byte=0)
        with self.assertRaisesRegex(ValueError, "0xFF"):
            image.verify_blank_skip(skip_blank=0x1000, blank_byte=0)
        opts = SimpleNamespace(decompress=False, skip_blank=0x1000, blank_byte=0)
        with self.assertRaisesRegex(SystemExit, "0xFF"):
            vbflasher._wire_blocks_for(image, opts)

    def test_flash_order_uses_written_span_for_compressed_image(self):
        first = Vbf.__new__(Vbf)
        first.path = "compressed.vbf"
        first.dfi = 0x10
        first.omit = []
        first.erase = []
        first._unpacked = {}
        payload = b"\xAA" * 0x5000
        packed = lzss_encode(payload)
        self.assertLess(len(packed), 0x2000)
        first.blocks = [dict(start=0x1000, length=len(packed),
                             data=packed, crc=0)]

        later = Vbf.__new__(Vbf)
        later.path = "later.vbf"
        later.dfi = None
        later.omit = []
        later.erase = [(0x3000, 0x1000)]
        later.blocks = [dict(start=0x3000, length=0x100,
                             data=b"\xBB" * 0x100, crc=0)]

        with self.assertRaisesRegex(SystemExit, "flash order would destroy"):
            vbflasher._check_flash_order([first, later])


if __name__ == "__main__":
    unittest.main()
