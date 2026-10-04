"""Regression vectors from the FORScan ABS flash/recovery captures."""
import unittest

import ecu_db
from ford_seckey import key_from_seed


class AbsCaptureTests(unittest.TestCase):
    # 0x760 request / 0x768 response: each 27 02 was accepted with 67 02.
    PAIRS = (
        ("forscan_flash2.log", "390000", "452154"),
        ("forscan_flash_mod.log", "7F6000", "68A1AB"),
        ("forscan_recovery.log", "1E2000", "9B501E"),
        ("forscan_recovery2.log", "DCB000", "993623"),
    )

    def test_level_one_secret_matches_all_accepted_keys(self):
        profile = ecu_db.get_profile(0x760)
        assert profile is not None
        secret = profile.pick_secret("", 1)
        self.assertEqual(secret, bytes.fromhex("42434D5932"))
        for filename, seed, key in self.PAIRS:
            with self.subTest(capture=filename):
                self.assertEqual(key_from_seed(bytes.fromhex(seed), secret),
                                 bytes.fromhex(key))

    def test_uncaptured_levels_keep_the_existing_fallback(self):
        profile = ecu_db.get_profile(0x760)
        assert profile is not None
        self.assertEqual(profile.pick_secret("", 3),
                         bytes.fromhex("42434D5932"))
        self.assertEqual(profile.pick_sbl("BV61-14C227-AA"),
                         "BV61-14C039-AA.vbf")
        self.assertTrue(profile.finalize)
        # The CV61/BV61 PBL replies are not yet proven for F1FC hardware.
        self.assertIsNone(profile.recovery_session_response)
        self.assertIsNone(profile.sbl_start_response)
        self.assertIsNone(profile.finalize_response)
        # Same reason: do not demand the 37 CRC echo be PRESENT profile-wide.
        # The mismatch check in download_blocks is unconditional anyway.
        self.assertFalse(profile.transfer_exit_crc)

    def test_transfer_exit_crc_echoes_are_the_files_stored_block_crcs(self):
        """Every 77 <crc16> in the captures matches a shipped ABS VBF block."""
        import binascii
        import os
        import vbf
        base = "/home/gl/Projects/ford/ABS/"
        # capture -> (file, block index, echoed crc)
        vectors = (
            ("all four", "BV61-14C039-AA.vbf", 0, 0x2D63),   # SBL
            ("flash2", "CV61-14C381-AH.vbf", 0, 0x2079),     # SIGCFG
            ("recovery2", "CV61-14C381-AE.vbf", 0, 0x919E),
            ("recovery", "CV61-14C036-AH.vbf", 0, 0xF1D1),
            ("recovery", "CV61-14C036-AH.vbf", 1, 0x5008),
            ("recovery", "CV61-14C036-AH.vbf", 3, 0xEEC2),
            ("recovery", "CV61-14C036-AH.vbf", 4, 0xE490),
        )
        for capture, name, bi, crc in vectors:
            with self.subTest(capture=capture, file=name, blk=bi):
                path = os.path.join(base, name)
                if not os.path.exists(path):
                    self.skipTest(f"{name} not available")
                blocks = vbf.Vbf(path).blocks or []
                b = blocks[bi]
                self.assertEqual(b["crc"], crc)
                self.assertEqual(
                    binascii.crc_hqx(b["data"][:b["length"]], 0xFFFF), crc)

    def test_the_modified_flash_echo_is_not_any_saved_build(self):
        """forscan_flash_mod's 3631/EB59 identify a build absent from disk."""
        import glob
        import vbf
        seen = set()
        for path in glob.glob("/home/gl/Projects/ford/ABS/*.vbf"):
            try:
                seen.update(b["crc"] for b in (vbf.Vbf(path).blocks or []))
            except Exception:                      # noqa: BLE001
                continue
        if not seen:
            self.skipTest("ABS VBFs not available")
        for crc in (0x3631, 0xEB59):
            self.assertNotIn(crc, seen)
        # ...while the stock pair it replaced IS on disk.
        for crc in (0xEEC2, 0xE490):
            self.assertIn(crc, seen)


if __name__ == "__main__":
    unittest.main()
