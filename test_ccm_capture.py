"""Regression vectors from the UCDS CCM (0x764 / 0x76C) flash captures.

Ground truth: /home/gl/Projects/ford/CCM/GV6T/ucds_flash.log holds the whole
prologue of a UCDS flash of the ESR radar; uscds.log is a second run that is
already inside the SBL when the capture starts.
"""
import os
import unittest

import ecu_db
import vbf
import vbflasher
from ford_seckey import key_from_seed


class CcmCaptureTests(unittest.TestCase):
    # ucds_flash.log: 27 01 -> 67 01 AC47B6, then 27 02 E0876D -> 67 02.
    SEED = "AC47B6"
    KEY = "E0876D"
    SECRET = "AACCCC3355"

    def profile(self) -> ecu_db.EcuProfile:
        p = ecu_db.get_profile(0x764)
        assert p is not None
        return p

    def test_level_one_secret_reproduces_the_accepted_key(self):
        secret = self.profile().pick_secret("", 1)
        self.assertEqual(secret, bytes.fromhex(self.SECRET))
        self.assertEqual(key_from_seed(bytes.fromhex(self.SEED), secret),
                         bytes.fromhex(self.KEY))

    def test_uncaptured_levels_fall_back_to_the_keybag_rule(self):
        self.assertEqual(self.profile().pick_secret("", 3),
                         bytes.fromhex(self.SECRET))

    def test_secret_resolves_with_no_hardware_string(self):
        # The module answers F113 (AG9N-9G768-BF), not F111, so secret/SBL
        # selection runs with hw == "". Every rule prefix must stay blank.
        p = self.profile()
        self.assertEqual(p.pick_secret("", 1), bytes.fromhex(self.SECRET))
        self.assertEqual(p.pick_sbl(""), "AE9T-14D051-AA.VBF")

    def test_pbl_signatures_from_the_capture(self):
        p = self.profile()
        # 10 02 -> 50 02 00 19 01 F4
        self.assertEqual(p.recovery_session_response,
                         bytes.fromhex("5002001901F4"))
        # 31 01 0301 03FF9000 -> 71 01 0301 10, full 4-byte call address
        self.assertEqual(p.sbl_start_response, bytes.fromhex("7101030110"))
        self.assertFalse(p.sbl_call_halfword)

    def test_finalise_and_transfer_exit_crc_from_the_capture_tail(self):
        # uscds.log ends: 37 -> 77 226F, 34/36.../37 -> 77 DDEF,
        # 31 01 0304 -> 71 01 0304 10 02, 11 01 -> 51 01.
        p = self.profile()
        self.assertTrue(p.finalize)
        self.assertEqual(p.finalize_response, bytes.fromhex("710103041002"))
        self.assertTrue(p.transfer_exit_crc)

    def test_finalise_gate_rejects_a_bare_positive_sid(self):
        p = self.profile()
        vbflasher.check_finalize_response(p, bytes.fromhex("710103041002"))
        for wrong in ("71010304", "710103041001"):
            with self.subTest(resp=wrong):
                with self.assertRaises(SystemExit):
                    vbflasher.check_finalize_response(
                        p, bytes.fromhex(wrong))

    def test_transfer_exit_crc_echo_matches_the_shipped_vbfs(self):
        """The CRCs the module echoed are the files' own stored block CRCs."""
        import binascii
        base = "/home/gl/Projects/ford/CCM/GV6T/"
        expected = {  # file -> the 77 <crc16> values seen in the captures
            "AE9T-14D051-AA.VBF": [0xC404],
            "GV6T-14D049-BD.VBF": [0x226F, 0xDDEF],
        }
        for name, crcs in expected.items():
            path = os.path.join(base, name)
            if not os.path.exists(path):
                self.skipTest(f"{name} not available")
            v = vbf.Vbf(path)
            self.assertEqual([b["crc"] for b in v.blocks], crcs)
            for b, want in zip(v.blocks, crcs):
                self.assertEqual(
                    binascii.crc_hqx(b["data"][:b["length"]], 0xFFFF), want)

    def test_crc_parser_ignores_a_bare_transfer_exit(self):
        self.assertIsNone(vbf.transfer_exit_crc(bytes.fromhex("77")))
        self.assertIsNone(vbf.transfer_exit_crc(None))
        self.assertEqual(vbf.transfer_exit_crc(bytes.fromhex("77226F")),
                         0x226F)


class TransferExitCrcGateTests(unittest.TestCase):
    """Drive the real download_blocks with a fake ECU answering 77 <crc16>."""

    class FakeEcu:
        execute = True

        def __init__(self, exit_resp):
            self.exit_resp = exit_resp

        def expect(self, req, sid, what, timeout=0, pending_timeout=0):
            if req.startswith("34"):
                return bytes.fromhex("74200082")
            if req == "37":
                return self.exit_resp
            raise AssertionError(req)

        def req(self, hexs, timeout=0, what=None):
            return bytes.fromhex("7601")

    def blocks(self):
        import binascii
        data = bytes(range(256)) * 2
        return [{"start": 0x8000, "length": len(data), "data": data,
                 "crc": binascii.crc_hqx(data, 0xFFFF)}]

    def _run(self, exit_resp, **kw):
        vbf.download_blocks(self.FakeEcu(exit_resp), self.blocks(), "t", **kw)

    def test_matching_crc_passes(self):
        b = self.blocks()[0]
        self._run(bytes([0x77, b["crc"] >> 8, b["crc"] & 0xFF]),
                  exit_crc=True)

    def test_mismatching_crc_aborts_even_without_the_flag(self):
        with self.assertRaises(SystemExit):
            self._run(bytes.fromhex("77DEAD"), exit_crc=False)

    def test_mismatching_crc_is_downgraded_by_force(self):
        self._run(bytes.fromhex("77DEAD"), exit_crc=False, force=True)

    def test_missing_crc_aborts_only_where_it_is_registered(self):
        self._run(bytes.fromhex("77"), exit_crc=False)       # normal elsewhere
        with self.assertRaises(SystemExit):
            self._run(bytes.fromhex("77"), exit_crc=True)
        self._run(bytes.fromhex("77"), exit_crc=True, force=True)


if __name__ == "__main__":
    unittest.main()
