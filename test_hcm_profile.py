"""HCM registry/CLI coverage. All transport is mocked; no CAN access."""
import contextlib
import io
import unittest
from unittest.mock import Mock, patch

import ecu_db
import vbflasher


class HcmProfileTests(unittest.TestCase):
    def test_hcm_resolves_to_captured_address_and_bus(self):
        profile = ecu_db.resolve('HCM')
        assert profile is not None
        for selector in ('hcm', '734', '0x734', 0x734):
            self.assertIs(ecu_db.resolve(selector), profile)
        self.assertEqual(profile.txid, 0x734)
        self.assertEqual(profile.resp_id(), 0x73C)
        self.assertEqual(profile.bus, 'HS-CAN')
        self.assertEqual(profile.default_iface(), 'can0')
        # Unknown programming details must not borrow another module's data.
        self.assertIsNone(profile.pick_secret('', 1))
        self.assertIsNone(profile.pick_secret('', 3))
        self.assertIsNone(profile.pick_sbl(''))

    def test_readdid_uses_hcm_profile_without_unlock(self):
        args = vbflasher.build_parser().parse_args(['readdid', 'HCM', '3B03', '3B05'])
        ecu = Mock(rxid=0x73C)
        ecu.req.side_effect = [bytes.fromhex('623B0300D3'), bytes.fromhex('623B0500C4')]
        output = io.StringIO()
        with (patch.object(vbflasher, '_check_iface') as check,
              patch.object(vbflasher, 'Ecu', return_value=ecu) as factory,
              contextlib.redirect_stdout(output)):
            vbflasher.do_readdid(args)
        check.assert_called_once_with('can0')
        factory.assert_called_once_with('can0', 0x734, 0x73C, execute=True)
        self.assertEqual([c.args[0] for c in ecu.req.call_args_list], ['223B03', '223B05'])
        ecu.expect.assert_not_called()
        self.assertIn('00D3', output.getvalue())
        self.assertIn('00C4', output.getvalue())


if __name__ == '__main__':
    unittest.main()
