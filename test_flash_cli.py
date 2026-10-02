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
