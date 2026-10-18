"""Offline tests for the `routine` (31 RoutineControl) subcommand. No CAN."""
import contextlib
import io
import unittest
from unittest.mock import Mock, patch

import vbflasher


def run(argv, responses):
    args = vbflasher.build_parser().parse_args(["routine", *argv])
    ecu = Mock(rxid=0x768)
    ecu.req.side_effect = responses
    out = io.StringIO()
    with (patch.object(vbflasher, "_check_iface"),
          patch.object(vbflasher, "Ecu", return_value=ecu),
          patch.object(vbflasher, "_session_and_unlock") as unlock,
          patch.object(vbflasher, "Keepalive") as ka,
          patch.object(vbflasher.time, "sleep") as sleep,
          contextlib.redirect_stdout(out)):
        rc = vbflasher.do_routine(args)
    return rc, ecu, out.getvalue(), unlock, ka, sleep


class RoutineTests(unittest.TestCase):
    def test_abs_ccc_learn_runs_both_routines_with_the_gap(self):
        rc, ecu, out, unlock, ka, sleep = run(
            ["ABS", "0E08", "0E06", "--yes", "--session", "0x03"],
            [bytes.fromhex("71010E0810"), bytes.fromhex("71010E0610")])
        self.assertEqual(rc, 0)
        self.assertEqual([c.args[0] for c in ecu.req.call_args_list],
                         ["31010E08", "31010E06"])
        unlock.assert_called_once()
        sleep.assert_called_once_with(15.0)
        ka.return_value.start.return_value.stop.assert_called_once()
        self.assertIn("status=10", out)

    def test_negative_or_missing_response_fails_but_keeps_going(self):
        rc, ecu, out, *_ = run(["ABS", "0E08", "0E06", "--yes", "--wait", "0"],
                               [bytes.fromhex("7F3122"), None])
        self.assertEqual(rc, 1)
        self.assertEqual(ecu.req.call_count, 2)
        self.assertIn("FAIL 0E08", out)
        self.assertIn("FAIL 0E06", out)

    def test_bad_routine_id_and_data_are_rejected_before_connecting(self):
        for argv in (["ABS", "E08", "--yes"],
                     ["ABS", "0E08", "--data", "ABC", "--yes"]):
            with self.subTest(argv=argv):
                args = vbflasher.build_parser().parse_args(["routine", *argv])
                with patch.object(vbflasher, "Ecu") as factory:
                    with self.assertRaises(SystemExit):
                        vbflasher.do_routine(args)
                factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
