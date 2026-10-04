"""The post-session settle before requestSeed must apply to EVERY module.

Ground truth: UCDS waits ~1.0 s between `50 02` and `27 01` on the CCM
(CCM/GV6T/ucds_flash.log: 50 02 at t=9.111, 27 01 at t=10.129). A module that
answers the session jumps into its primary bootloader and can refuse or drop a
requestSeed sent immediately after.
"""
import inspect
import unittest

import vbflasher


class SeedDelayTests(unittest.TestCase):
    def test_default_matches_the_ucds_capture(self):
        self.assertGreaterEqual(vbflasher.SEED_DELAY, 1.0)

    def test_helper_sleeps_and_honours_zero(self):
        slept = []
        real = vbflasher.time.sleep
        vbflasher.time.sleep = slept.append
        try:
            vbflasher.settle_before_seed(1.0)
            vbflasher.settle_before_seed(0)
        finally:
            vbflasher.time.sleep = real
        self.assertEqual(slept, [1.0])

    def _src_before_seed(self, func):
        """Source of func, truncated at its first requestSeed REQUEST."""
        src = inspect.getsource(func)
        # Match the request itself, not the word in a comment.
        idx = src.find('expect(f"27{level:02X}"')
        self.assertGreater(idx, 0, f"{func.__name__} sends no requestSeed")
        return src[:idx]

    def test_every_requestSeed_site_settles_first(self):
        # Each of these opens a session and then asks for a seed. None may fall
        # back to a bare short sleep -- that was the 0.1 s we replaced.
        for func in (vbflasher.flash_session,
                     vbflasher._open_sbl_session,
                     vbflasher._session_and_unlock):
            with self.subTest(func=func.__name__):
                head = self._src_before_seed(func)
                self.assertIn("settle_before_seed(", head)

    def test_flag_is_exposed_on_every_command_that_unlocks(self):
        import argparse
        ap = vbflasher.build_parser()
        subs = next(a for a in ap._actions
                    if isinstance(a, argparse._SubParsersAction))
        for cmd in ("flash", "readdid", "writedid", "memread", "memwrite"):
            with self.subTest(cmd=cmd):
                opts = {s for a in subs.choices[cmd]._actions
                        for s in a.option_strings}
                self.assertIn("--seed-delay", opts)

    def test_flag_reaches_the_parsed_args(self):
        ap = vbflasher.build_parser()
        args = ap.parse_args(["flash", "x.vbf", "--seed-delay", "2.5"])
        self.assertEqual(args.seed_delay, 2.5)
        args = ap.parse_args(["flash", "x.vbf"])
        self.assertEqual(args.seed_delay, vbflasher.SEED_DELAY)


if __name__ == "__main__":
    unittest.main()
