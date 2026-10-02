#!/usr/bin/env python3
"""Candidate SecurityAccess secrets ("keybag") for the dictionary attack.

PROVENANCE
----------
Every entry is transcribed verbatim from FoCCCus
`/home/gl/Dropbox/QtProj/FoCCCus/ford_c346.cpp`, function
`c346::bruteSecretKey()`, which appends them to a QList<QByteArray> and tries
each against a live module. The file lists 398 appends; 55 are exact duplicates
(FoCCCus retries them), so the 343 unique values below are kept in first-seen
order — that order is itself information, as FoCCCus front-loads the secrets it
has seen most often in the wild.

A "secret" here is the 5-byte value fed to ford_seckey.key_from_seed, most
significant byte first (the FoCCCus QByteArray::fromHex order).

THIS IS A DICTIONARY, NOT A BRUTE FORCE. The keyspace is 2^40; these 343
candidates are the secrets observed in Ford/Mazda/Volvo tools and dumps. A miss
means "not in this dictionary", never "no secret exists".
"""

# Candidate secrets, first-seen order from ford_c346.cpp bruteSecretKey().
KEYBAG = (
    "50000A241D", "083061A4C5", "C5A4613008", "64000B0C59", "CD0D52F64D", "AA775C45B7",
    "79699656B6", "1A12D39849", "766684578C", "8899966A5C", "98976877AA", "93469848B9",
    "9699569485", "9CCA8A7A37", "79B68CA464", "177B6A9674", "7B73776AA5", "A86B9C8768",
    "98859877A9", "27767659C6", "7537BBD889", "87C88B77A6", "34D952C942", "7DD0C47662",
    "6AA568565E", "49BE982A14", "08306155AA", "536798B3A4", "B397C86A37", "06F9049E65",
    "B6E3D77C3D", "92776B8877", "7B87899B57", "388985873A", "9AB6996C9A", "7877686B53",
    "7787A586A3", "5C55289B6D", "D1F32D914B", "2311D2A267", "9977888877", "A76CB279AA",
    "9487A9A67A", "AA76886BA7", "B3B32303A6", "6D82307101", "96878894A8", "977AD93C82",
    "3004AA9A7A", "511B537474", "B50AB4962C", "A2A3ACCA50", "8577C86536", "595B587252",
    "20AC715FF7", "3CE2DB419A", "835507519A", "42434D5932", "44494F4445", "583582C81D",
    "3F43EF74BE", "E8D2066DDC", "714877B24B", "1D61E5C70D", "064E9AE1DE", "6C2EA071E6",
    "89D57FB3A7", "AACCCC3355", "76C47FE500", "47A73B8362", "B314F11A05", "081A78BBE7",
    "0853ACDE3D", "519A72131C", "E729D14B41", "F6920244E0", "4F534E4544", "AA7C3ABDD9",
    "DC0DE5B1AB", "6C5AB3C78B", "B26D749A57", "5F7DF5F793", "9D6CC312BB", "E6A402D16A",
    "3132333435", "ABDC7445C6", "06C3036B0B", "85EFF9F5DC", "335900298A", "A5B3EFDA76",
    "07F56AF947", "AEC7B44BAC", "6406D6A6C0", "3D804983B3", "A5FD4C45DA", "FDB3F43588",
    "8A81A88882", "6577780412", "0000000000", "4D617A6441", "0101010101", "121701E394",
    "4182F678EE", "C3A1097714", "2E67CB8A03", "CA5B1B48AF", "DEB4772704", "7B03C922F1",
    "415249414E", "4A65737573", "134B7CF35C", "52454D4154", "54414D4552", "97627984EC",
    "4157544355", "0824760111", "41AA42BB43", "3A6293D6F7", "2E67CB8A30", "1223344556",
    "ADD9A26775", "AABBCCDDEE", "05B7062503", "11410298E3", "2D86C557A1", "414953494E",
    "61EBADC624", "466E74634D", "4467AAF207", "227B3F2377", "FE4228D3AD", "454D453153",
    "54524F4853", "CE0891A643", "341F3CFBC5", "3149216327", "526F77616E", "2468864204",
    "F732D73A12", "F4791A60CB", "5A3B514A35", "2CD873A914", "1617010815", "4452494654",
    "C5A461A4A7", "08305561AA", "48415A454C", "7D2D200578", "2431DEF946", "0123456789",
    "A3B2C01492", "CB41122871", "C414021105", "1E08171B72", "0109FF1964", "151F521F7F",
    "0C04491562", "1C27507677", "0168A478A1", "57A2F7C349", "167E04CFF5", "19AC3A1CC2",
    "3A8ECF9CCE", "3F3A2F2101", "F8A95F1D01", "35E7FA6DD1", "0A6DC13B20", "22A16051A9",
    "0D5ADBDFCA", "9F754B3B87", "225FB4AC54", "F4310FB252", "2964B272C2", "F83912960E",
    "AA5A35BED4", "96A23B839B", "C89B10488D", "75B156834A", "488729889D", "5E18BF9B75",
    "A6379E8434", "114D8775AF", "0EAA0BA016", "F51E1487C0", "1CF000C10A", "58053E459C",
    "4555434431", "DCD5447AE6", "544F424245", "485354434D", "1F1A4F3EE6", "1524334251",
    "18AE784AD2", "C9EA84CB10", "2592CA3429", "FA6B5A7047", "FFFFFFFFFF", "AC031489E3",
    "ACF72992E1", "DD161A48AF", "4976666552", "0828211663", "0A160407B6", "1B44144D24",
    "2205120906", "4151268411", "4812A6D57B", "4A36314346", "4E53594E53", "5061446D41",
    "5F9C99A350", "6A5568515E", "6E6F776152", "886D91757D", "D8415D77A5", "4C7570696E",
    "8C00000000", "8C54F80BD7", "53484F5741", "4776666552", "268CB471EE", "AB7DD1D271",
    "8CF5A519EE", "6969B653A1", "4C4341424C", "268145297D", "288145297D", "DACCCB6EB3",
    "434F4C494E", "16B9137770", "4D48657179", "6248C5A25F", "5A89E44172", "4272616457",
    "4A616E6973", "8A789034F7", "50C86A49F1", "0225197707", "0102030405", "2487647032",
    "2487646585", "61422B5464", "16652CEABE", "8C4AD21F2E", "DC400A5923", "839EE212E0",
    "464D433031", "C1B0CAD01A", "38078A63C1", "B83F247FFF", "534B6521AD", "27A12B1983",
    "84660862AB", "A31307047D", "6456364CA7", "1122334455", "836ACF361B", "03D6B5D76F",
    "8C020D045F", "984B9408E7", "08036155AA", "624B9408E7", "882A7B9336", "DF3A1469C2",
    "0406070409", "053C703A75", "E184BE2329", "A3C1E41989", "715521A55E", "869A784D90",
    "7155215EA5", "71552141C2", "42D36E34CE", "42DD6E34CE", "835707339A", "882A7B9354",
    "13F129B301", "5B4174657D", "50C86A49F2", "A7C2E91992", "A7C2E92C7A", "44DD45EE46",
    "204AFE9C2D", "3163466648", "E9D4A11201", "426F736368", "37E1A215C8", "6BA7430A71",
    "162738495A", "6F6E696268", "626861776E", "615F626164", "5CEB117B30", "001D460F63",
    "7118A56868", "C8B2E39E76", "FD4C9281ED", "7118416968", "3F375F2259", "4E8AE2CAD8",
    "6538743631", "B6451777D3", "21A4396C04", "0A1E0514C2", "7C70D030C1", "636F6E7469",
    "6BA7240A71", "1A2B3C4D5E", "F311454C73", "1746CEB435", "9A78563412", "76AB510945",
    "3423391177", "4151268401", "2403356384", "8408F57701", "1982061003", "424F534558",
    "666F617765", "53554D2D33", "1213197630", "42A4839979", "EFE57A916A", "19D30B2FD2",
    "1420E6890A", "5E100F4633", "1571031976", "66AF300612", "20E448E1D1", "28E222635F",
    "083161A4C5", "E6763FED74", "4A414D4553", "0808010301", "5475BC4E68", "4D415A4441",
    "4B30323136", "6D415A4461", "621C067260", "50414E4441", "212703DA27", "2270EA4C11",
    "466C617368",
)


# --------------------------------------------------------------------------
# Second tier: secrets NOT present in the FoCCCus list, harvested from other
# public Ford tools. Searched after KEYBAG, IPC-relevant entries first.
#
# Sources (cloned and parsed, not copied by hand):
#   * jakka351/FG-Falcon  SPECIFICATIONS/Secret Keys/*.key — Ford's own
#     <SECURITY_INFO><FIXED_BYTE> XML format, one file per module address.
#     720II.key is a SECOND IPC key set (hence "II"), i.e. a different cluster
#     supplier than 720.key.
#   * jakka351/FG-Falcon  FG1.py — per-module {address: {level: secret}} table
#     plus a hardcoded `fixed = 0xBFA49056CD` supplierKeyGen (VDO cluster).
#   * jakka351/Ford-ECU-Bruteforcer  Sample/security.cs — a 242-entry C#
#     keybag (187 unique; all but a handful already in KEYBAG) and a commented
#     "sEcReT KeYs fRoM fOrScaN" list of 5-character ASCII words.
#
# The per-module notes are the ORIGINAL author's attribution, kept because a
# secret attested for 0x720 is worth trying first on an IPC. They are NOT
# verified here: several sources disagree with each other (FG1.py lists both
# 0xFA5FC0 and 0xBFA49056CD for 0x720 level 1), and short values were
# zero-padded to 5 bytes, which is an assumption about intent.
#
# Checked and found to contain NO Ford secrets: jglim/UnlockECU db.json
# (3038 entries, all Daimler/Honda/Subaru/KIA), jakka351/0x27 (an UnlockECU
# fork), jakka351/SecurityAccess0x27. jakka351/FG-Falcon-CAN-Logs holds live
# brute-force captures whose 339 on-the-wire sendKey payloads are all already
# in KEYBAG — which independently confirms KEYBAG is the superset of that tool.
KEYBAG_EXT = (
    "000092C13B",     # modules 0x703,0x720 lvl 0x03
    "0000FA5FC0",     # modules 0x703,0x720 lvl 0x01
    "0926F26388",     # modules 0x720 lvl 0x11
    "21836A41D9",     # modules 0x720 lvl 0x1
    "40E234995F",     # modules 0x720 lvl 0x03,0x3
    "BFA49056CD",     # modules 0x720,0x760 lvl 0x01; hardcoded supplier secret
    "000006316B",     # modules 0x760 lvl 0x11
    "0000128665",     # modules 0x726,0x7A6 lvl 0x11
    "0000462A71",     # modules 0x731 lvl 0x11
    "00004AD0FB",     # modules 0x727 lvl 0x03
    "0000582613",     # modules 0x760 lvl 0x01
    "0000672A70",     # modules 0x731 lvl 0x01
    "000076807F",     # modules 0x760 lvl 0x03
    "00009B2533",     # modules 0x730,0x7A6 lvl 0x01 (our PSCM secret)
    "0000FAA8BD",     # modules 0x726 lvl 0x01
    "48375594A9",     # modules 0x726 lvl 0x1; C# keybag
    "0000123456",     # hardcoded supplier secret
    "2D4D45724D",     # C# keybag; ForScan word '-MErM'
    "2E5465645C",     # ForScan word '.Ted\\'
    "424F534348",     # C# keybag; ForScan word 'BOSCH'
    "42726F576E",     # C# keybag; ForScan word 'BroWn'
    "4361726F6C",     # ForScan word 'Carol'
    "446F575A79",     # C# keybag
    "4641495448",     # C# keybag; ForScan word 'FAITH'
    "466C617306",     # C# keybag
    "47414E4553",     # C# keybag; ForScan word 'GANES'
    "4A614D6573",     # C# keybag; ForScan word 'JaMes'
    "4C41555241",     # C# keybag; ForScan word 'LAURA'
    "4D41434F4D",     # C# keybag; ForScan word 'MACOM'
    "4F75547559",     # ForScan word 'OuTuY'
    "53414D4D59",     # C# keybag; ForScan word 'SAMMY'
    "534B414E44",     # C# keybag; ForScan word 'SKAND'
    "57414C795C",     # ForScan word 'WALy\\'
    "657548554E",     # ForScan word 'euHUN'
    "6B626F6241",     # ForScan word 'kbobA'
    "7045646520",     # ForScan word 'pEde '
    "736C496F72",     # C# keybag; ForScan word 'slIor'
    "EF3484ABEA",     # C# keybag
)


def candidates(extra=(), first=(), ext=True):
    """Return the keybag as 5-byte values, de-duplicated, order preserved.

    first : secrets to try BEFORE the dictionary (e.g. the ones ecu_db already
            registers for this ECU — if one of them works there is nothing to
            search for).
    extra : secrets to append after the dictionary.
    ext   : include KEYBAG_EXT (the non-FoCCCus sources). Pass False to
            reproduce a FoCCCus-only run exactly.
    """
    out, seen = [], set()
    for src in (first, KEYBAG, KEYBAG_EXT if ext else (), extra):
        for item in src:
            b = bytes.fromhex(item) if isinstance(item, str) else bytes(item)
            if len(b) != 5:
                raise ValueError(f"secret must be 5 bytes, got {b.hex()}")
            if b not in seen:
                seen.add(b)
                out.append(b)
    return out


if __name__ == "__main__":
    c = candidates()
    print(f"{len(KEYBAG)} FoCCCus + {len(KEYBAG_EXT)} other-source entries, "
          f"{len(c)} unique candidates")
    print("first 8:", ", ".join(x.hex().upper() for x in c[:8]))
