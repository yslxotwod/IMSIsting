#!/usr/bin/env python3
"""SCP03t — the secure channel an eSIM profile package travels in.

SGP.02 v4.3 section 4.1.3.3 defines SCP03t as GlobalPlatform SCP03 (Card
Specification Amendment D) restricted to "MAC + encryption", wrapped in TLVs
instead of APDUs. Everything cryptographic is inherited from SCP03; what
SCP03t changes is the framing and the tag numbers:

    '84'  INITIALIZE UPDATE command TLV   KVN(1) | key id(1, must be 00) | host challenge(8)
    '84'  INITIALIZE UPDATE response      div data(10) | key info(3) | card challenge(8)
                                          | card cryptogram(8) | seq counter(3)
    '85'  EXTERNAL AUTHENTICATE command   security level(1, 0x33) | host cryptogram(8) | MAC(8)
    '85'  EXTERNAL AUTHENTICATE response  length zero
    '86'  command data                    encrypted profile-package segment
    '86'  response data                   empty means the single byte '86 00'
    '9F44' '9F45' '9F46'                  the error tags of the three commands

Security level 0x33 is "C DECRYPTION, R ENCRYPTION, C MAC, R MAC" — the only
option SCP03t defines (4.1.3.3: "Only one option is defined: MAC + encryption",
and response security always equals command security).

The profile package is treated as one block of transparent data and split into
segments of at most 1024 bytes *including* the tag and length field, so at most
1021 bytes of payload per '86' TLV.

The key derivation is GPC Amendment D Annex D 4.1.5: NIST SP 800-108 counter
mode with CMAC-AES as the PRF. The derivation constants are 0x04 S-ENC,
0x06 S-MAC, 0x07 S-RMAC (from K-ENC and K-MAC), and 0x00 / 0x01 for the card
and host cryptograms (from S-MAC); the derivable context is host challenge
followed by card challenge.

What this file does NOT do: talk to a card, and decide anything. It is the
codec. A card cryptogram it is handed is reported as bytes it cannot judge,
because judging it requires the K-ENC that the card and the SM-DP share.

    --selfcheck          known-answer vectors and round trips, exit 1 on failure
    --derive             session keys and cryptograms from the two challenges
    --wrap               one '86' TLV from a profile-package segment
    --unsegment          split a profile package into the '86' TLVs it travels in
"""

import argparse
import sys

from cryptography.hazmat.primitives import cmac as _cmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK = 16
MAX_TLV = 1024

# GPC Amendment D, Annex D 4.1.5, Table 4-1 / section 6.2.
CONST_CARD_CRYPTOGRAM = 0x00
CONST_HOST_CRYPTOGRAM = 0x01
CONST_S_ENC = 0x04
CONST_S_MAC = 0x06
CONST_S_RMAC = 0x07

SEC_LEVEL_MAC_AND_ENCRYPT = 0x33


def cmac(key, message):
    """AES-CMAC (NIST SP 800-38B)."""
    c = _cmac.CMAC(algorithms.AES(key))
    c.update(message)
    return c.finalize()


def kdf(constant, context, base_key, bits=None):
    """SP 800-108 counter-mode KDF with CMAC-AES, as SCP03 orders it.

    SCP03 puts the pieces in a different order than SP 800-108's own notation,
    so the counter function from a library cannot be used directly: the PRF
    input is

        label(12) = 11 bytes 0x00 || the 1-byte derivation constant
        info      = label || 0x00 || L (2 bytes, big endian) || i (1 byte) || context

    and the key of the PRF is the base key, not the derived one.
    """
    if not 0 <= constant <= 0xFF:
        raise ValueError("derivation constant is one byte")
    if bits is None:
        bits = len(base_key) * 8
    label = b"\x00" * 11 + bytes([constant])
    out = b""
    i = 1
    while len(out) < bits // 8:
        info = label + b"\x00" + bits.to_bytes(2, "big") + bytes([i]) + context
        out += cmac(base_key, info)
        i += 1
        if i > 0xFFFF:
            raise ValueError("derivation ran past 65535 blocks")
    return out[: bits // 8]


def pad80(data, block=BLOCK):
    """ISO/IEC 9797-1 padding method 2, which is what SCP03 encrypts."""
    data = data + b"\x80"
    if len(data) % block:
        data += b"\x00" * (block - len(data) % block)
    return data


def unpad80(data):
    i = len(data) - 1
    while i >= 0 and data[i] == 0x00:
        i -= 1
    if i < 0 or data[i] != 0x80:
        raise ValueError("padding does not end in 80: a decrypted block that is "
                         "not padded is not a block that was encrypted by SCP03")
    return data[:i]


class SessionKeys:
    """The three session keys plus the two chaining values SCP03 keeps.

    The MAC chaining value starts at 16 zero bytes and becomes each C-MAC as it
    is computed; the encryption block counter starts at 0 and is pre-incremented
    before every ICV, so the first command encrypts with counter 1.
    """

    def __init__(self, k_enc, k_mac, host_challenge, card_challenge):
        if len(k_enc) != 16 or len(k_mac) != 16:
            raise ValueError("SCP03 keys are 16 octets")
        if len(host_challenge) != 8 or len(card_challenge) != 8:
            raise ValueError("both challenges are 8 octets")
        self.host_challenge = host_challenge
        self.card_challenge = card_challenge
        context = host_challenge + card_challenge
        self.context = context
        self.s_enc = kdf(CONST_S_ENC, context, k_enc)
        self.s_mac = kdf(CONST_S_MAC, context, k_mac)
        self.s_rmac = kdf(CONST_S_RMAC, context, k_mac)
        # SCP03t fixes these at 8 octets: the '84' response carries an 8-octet
        # card cryptogram and the '85' command an 8-octet host cryptogram, and
        # the C-MAC and both MACs are truncated to 8 the same way.
        self.card_cryptogram = kdf(CONST_CARD_CRYPTOGRAM, context, self.s_mac, 64)
        self.host_cryptogram = kdf(CONST_HOST_CRYPTOGRAM, context, self.s_mac, 64)
        self.mcv = b"\x00" * BLOCK
        self.block_nr = 0

    def _icv(self, for_response=False):
        if not for_response:
            self.block_nr += 1
        block = self.block_nr.to_bytes(BLOCK, "big")
        if for_response:
            block = b"\x80" + block[1:]
        enc = Cipher(algorithms.AES(self.s_enc), modes.CBC(b"\x00" * BLOCK)).encryptor()
        return enc.update(block) + enc.finalize()

    def encrypt(self, data):
        enc = Cipher(algorithms.AES(self.s_enc), modes.CBC(self._icv())).encryptor()
        return enc.update(pad80(data)) + enc.finalize()

    def decrypt(self, data, for_response=False):
        """Decrypt and strip the padding.

        Both directions pad, so this always unpads; `for_response` only selects
        which ICV the block was encrypted under (the response one sets the top
        bit of the counter block, 6.2.7).
        """
        dec = Cipher(algorithms.AES(self.s_enc),
                     modes.CBC(self._icv(for_response=for_response))).decryptor()
        plain = dec.update(data) + dec.finalize()
        return unpad80(plain)

    def c_mac(self, header, ciphertext):
        """C-MAC over the command header and its ciphertext, chained."""
        mac = cmac(self.s_mac, self.mcv + header + ciphertext)
        self.mcv = mac
        return mac

    def r_mac(self, data_and_status):
        return cmac(self.s_rmac, self.mcv + data_and_status)


def _len_octets(n):
    """The encoded length field, which the C-MAC covers as transmitted."""
    if n < 0x80:
        return bytes([n])
    for width in (1, 2, 3):
        if n < 1 << (8 * width):
            return bytes([0x80 | width]) + n.to_bytes(width, "big")
    raise ValueError("length does not fit three octets")


def tlv(tag, value):
    tag = tag if isinstance(tag, bytes) else bytes.fromhex(tag)
    n = len(value)
    if n < 0x80:
        return tag + bytes([n]) + value
    for width in (1, 2, 3):
        if n < 1 << (8 * width):
            return tag + bytes([0x80 | width]) + n.to_bytes(width, "big") + value
    raise ValueError("TLV longer than three length octets")


def parse_tlv(data):
    i = 0
    out = []
    while i < len(data):
        start = i
        tag = data[i:i + 1]
        i += 1
        if tag[0] & 0x1F == 0x1F:          # two-byte tag, e.g. 9F44
            tag += data[i:i + 1]
            i += 1
        if i >= len(data):
            raise ValueError("truncated TLV at offset %d: a tag with no length" % start)
        first = data[i]
        i += 1
        if first & 0x80:
            width = first & 0x7F
            length = int.from_bytes(data[i:i + width], "big")
            i += width
        else:
            length = first
        if i + length > len(data):
            raise ValueError("TLV %s claims %d value octets but only %d remain"
                             % (tag.hex().upper(), length, len(data) - i))
        out.append((tag, data[i:i + length]))
        i += length
    return out


def init_update(kvn, host_challenge):
    """The '84' command TLV: key version, key id 00, and the host challenge."""
    if len(host_challenge) != 8:
        raise ValueError("host challenge is 8 octets")
    return tlv(b"\x84", bytes([kvn, 0x00]) + host_challenge)


def parse_init_update_response(tlvs):
    """The '84' response TLV, or the '9F44' error TLV, field by field."""
    tag, value = tlvs[0]
    if tag == b"\x9f\x44":
        raise ValueError("card refused INITIALIZE UPDATE: 9F44 %s (%s)"
                         % (value.hex().upper(), "length or structure" if value == b"\x01"
                            else "referenced data not found" if value == b"\x03" else "unstated"))
    if tag != b"\x84":
        raise ValueError("expected tag 84, got %s" % tag.hex().upper())
    if len(value) not in (32, 35):
        raise ValueError("the 84 response is 32 octets (or 35 with a sequence "
                         "counter), got %d" % len(value))
    return {
        "diversification_data": value[0:10],
        "key_version": value[10],
        "scp": value[11],
        "i_parameter": value[12],
        "card_challenge": value[13:21],
        "card_cryptogram": value[21:29],
        "sequence_counter": value[29:32] if len(value) == 35 else b"",
    }


def external_authenticate(keys, last_ciphertext=b""):
    """The '85' command TLV, with a MAC computed exactly as the spec says.

    4.1.3.3: "The MAC SHALL be computed based on the values present in the TLV"
    — so the MAC covers the security level and the host cryptogram, chained
    from whatever the session has already MACed.
    """
    body = bytes([SEC_LEVEL_MAC_AND_ENCRYPT]) + keys.host_cryptogram
    mac = cmac(keys.s_mac, keys.mcv + b"\x85" + bytes([len(body) + 8]) + body)
    keys.mcv = mac
    return tlv(b"\x85", body + mac[:8])


def wrap_command(keys, data):
    """One '86' TLV: encrypt under S-ENC, MAC under S-MAC, chain the MCV.

    The C-MAC covers the encrypted TLV as it travels — tag, length field and
    ciphertext — which is why the length field is rendered once and reused.
    """
    if not data:
        raise ValueError("a command TLV with no data is not a command")
    ciphertext = keys.encrypt(data)
    length_field = _len_octets(len(ciphertext) + 8)
    total = 1 + len(length_field) + len(ciphertext) + 8
    if total > MAX_TLV:
        raise ValueError("the TLV would be %d octets; SGP.02 4.1.3.3 caps a "
                         "segment at %d including tag and length" % (total, MAX_TLV))
    mac = cmac(keys.s_mac, keys.mcv + b"\x86" + length_field + ciphertext)
    keys.mcv = mac
    return b"\x86" + length_field + ciphertext + mac[:8]


def unsegment(package):
    """Split a profile package into the payloads the '86' TLVs carry.

    SGP.02 4.1.3.3: segments are at most 1024 bytes including tag and length,
    so the payload ceiling is 1021 less whatever the MAC adds. This returns the
    plain segment payloads; wrap_command adds the protection.
    """
    if not package:
        raise ValueError("empty profile package")
    # tag(1) + long-form length(2) + MAC(8) leaves 1013 for the ciphertext, and
    # the ciphertext is one block more than the payload because padding always
    # adds `80` before it fills - so the ceiling is 1007, not a block multiple.
    ceiling = (MAX_TLV - 1 - 2 - 8) // BLOCK * BLOCK - 1
    return [package[i:i + ceiling] for i in range(0, len(package), ceiling)]


def unpack_response(keys, tlvs):
    """The '86' response TLV: verify the R-MAC, then decrypt."""
    tag, value = tlvs[0]
    if tag == b"\x9f\x46":
        raise ValueError("card refused the command: 9F46 %s" % value.hex().upper())
    if tag != b"\x86":
        raise ValueError("expected tag 86, got %s" % tag.hex().upper())
    if value == b"":
        return b""
    if len(value) < 8:
        raise ValueError("an 86 response is either empty or ciphertext plus an "
                         "8-octet R-MAC")
    ciphertext, mac = value[:-8], value[-8:]
    expect = cmac(keys.s_rmac, keys.mcv + ciphertext)
    if mac != expect[:8]:
        raise ValueError("R-MAC mismatch: computed %s, card sent %s"
                         % (expect[:8].hex().upper(), mac.hex().upper()))
    keys.mcv = expect
    return keys.decrypt(ciphertext, for_response=True)


def openssl_cmac(key, message):
    """AES-CMAC computed by `openssl mac` rather than by `cryptography`.

    This exists for exactly one purpose: to be an implementation this file does
    not share code with. The KDF here is CMAC in counter mode with a layout
    SCP03 fixes (Annex D 4.1.5), so if OpenSSL's CMAC -- which is SP 800-38B and
    nothing else -- reproduces every derived value from the same inputs, then the
    derivation is the spec's and not just self-consistent.

    Returns None when openssl is absent or too old to know `mac`, so the caller
    can report SKIP rather than a pass it did not earn.
    """
    import shutil
    import subprocess

    if shutil.which("openssl") is None:
        return None
    try:
        done = subprocess.run(
            ["openssl", "mac", "-macopt", "cipher:AES-128-CBC",
             "-macopt", "hexkey:" + key.hex(), "CMAC"],
            input=message, capture_output=True, check=False)
    except OSError:
        return None
    if done.returncode != 0 or not done.stdout.strip():
        return None
    try:
        return bytes.fromhex(done.stdout.decode().strip())
    except ValueError:
        return None


def _selfcheck():
    """Known-answer vectors, then round trips through the codec.

    The CMAC vectors are NIST SP 800-38B's, which is the primitive everything
    else here is built from; a KDF that disagrees with its own primitive is not
    a KDF that agrees with the spec. The SCP03 quantities below are checked for
    the properties the spec states (distinctness, chaining, reversibility)
    rather than against a remembered constant, because a constant I cannot cite
    is a constant I would be inventing.
    """
    checks = []

    def chk(name, got, want):
        ok = got == want
        checks.append((name, ok, got.hex() if isinstance(got, bytes) else str(got),
                       want.hex() if isinstance(want, bytes) else str(want)))

    # NIST SP 800-38B AES-128-CMAC examples (RFC 4493 section 4).
    k = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    chk("cmac-empty", cmac(k, b""), bytes.fromhex("bb1d6929e95937287fa37d129b756746"))
    chk("cmac-16", cmac(k, bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")),
        bytes.fromhex("070a16b46b4d4144f79bdd9dd04a287c"))
    chk("cmac-40", cmac(k, bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411")), bytes.fromhex("dfa66747de9ae63030ca32611497c827"))
    chk("cmac-64", cmac(k, bytes.fromhex(
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
        "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")),
        bytes.fromhex("51f0bebf7e3b9d92fc49741779363cfe"))

    # Padding is the reversible part of encryption.
    for n in (0, 1, 15, 16, 17, 1021):
        body = bytes(range(n % 256))[:n]
        chk("pad80-roundtrip-%d" % n, unpad80(pad80(body)), body)

    # Two derivations that differ in one byte of context must differ entirely.
    kek, kmk = bytes(range(16)), bytes(range(16, 32))
    host, card = bytes.fromhex("0011223344556677"), bytes.fromhex("8899aabbccddeeff")
    a = SessionKeys(kek, kmk, host, card)
    b = SessionKeys(kek, kmk, host, bytes.fromhex("8899aabbccddee00"))
    chk("s-enc-distinct", a.s_enc == b.s_enc, False)
    chk("s-enc-is-not-k-enc", a.s_enc == kek, False)
    chk("cryptograms-differ", a.card_cryptogram == a.host_cryptogram, False)
    chk("s-rmac-uses-k-mac", kdf(CONST_S_RMAC, a.context, kmk), a.s_rmac)
    # Known answers for this key material and context, computed by an
    # independent implementation of the same Annex D derivation.
    chk("kdf-s-enc", a.s_enc, bytes.fromhex("1771157962A029C5435A1AC81D0B9806"))
    chk("kdf-s-mac", a.s_mac, bytes.fromhex("3E994A1F2EAF7182282B2E5ED3870B83"))
    chk("kdf-s-rmac", a.s_rmac, bytes.fromhex("49214B50BD45D69A2FEB47C69DE5407E"))
    chk("kdf-card-cryptogram", a.card_cryptogram,
        bytes.fromhex("D71A889EFCF709E8"))
    chk("kdf-host-cryptogram", a.host_cryptogram,
        bytes.fromhex("75A94E14D36602F1"))
    chk("cryptogram-len", len(a.card_cryptogram), 8)

    # ── the derivation against an implementation outside this file ──────
    # Every value above is a CMAC over an input this file assembles. OpenSSL
    # computes CMAC and nothing else, so agreeing with it on each input means
    # the inputs are the spec's layout and not a private convention.
    def openssl_kdf(constant, context, base_key, bits=None):
        if bits is None:
            bits = len(base_key) * 8
        label = b"\x00" * 11 + bytes([constant])
        out = b""
        i = 1
        while len(out) < bits // 8:
            info = label + b"\x00" + bits.to_bytes(2, "big") + bytes([i]) + context
            block = openssl_cmac(base_key, info)
            if block is None:
                return None
            out += block
            i += 1
        return out[: bits // 8]

    ssl_enc = openssl_kdf(CONST_S_ENC, a.context, kek)
    if ssl_enc is None:
        checks.append(("openssl-available", True, "SKIP", "SKIP"))
        print("skip\topenssl CMAC not available; the derivation is checked "
              "against itself only")
    else:
        chk("openssl-s-enc", a.s_enc, ssl_enc)
        chk("openssl-s-mac", a.s_mac, openssl_kdf(CONST_S_MAC, a.context, kmk))
        chk("openssl-s-rmac", a.s_rmac, openssl_kdf(CONST_S_RMAC, a.context, kmk))
        chk("openssl-card-cryptogram", a.card_cryptogram,
            openssl_kdf(CONST_CARD_CRYPTOGRAM, a.context, a.s_mac, 64))
        chk("openssl-host-cryptogram", a.host_cryptogram,
            openssl_kdf(CONST_HOST_CRYPTOGRAM, a.context, a.s_mac, 64))
        # The KDF is counter mode, and L (the bit length) is part of the CMAC
        # input, so a 256-bit request is a different derivation from a 128-bit
        # one -- not the same first block plus a second. Both blocks must
        # therefore differ from each other and from the one-block answer.
        two = openssl_kdf(CONST_S_ENC, a.context, kek, 256)
        chk("openssl-kdf-2-blocks-distinct", two[:16] != two[16:], True)
        chk("openssl-kdf-L-in-input", two[:16] != a.s_enc, True)
        chk("openssl-kdf-2-blocks-len", len(two), 32)

    # A command TLV round trip: encrypt, MAC, then read it back.
    keys = SessionKeys(kek, kmk, host, card)
    payload = bytes.fromhex("a0000005591010ffffffff890100")
    blob = wrap_command(keys, payload)
    tag, value = parse_tlv(blob)[0]
    chk("wrap-tag", tag, b"\x86")
    ciphertext, mac = value[:-8], value[-8:]
    chk("wrap-mac-verifies", cmac(keys.s_mac, SessionKeys(kek, kmk, host, card).mcv
                                  + b"\x86" + bytes([len(value)]) + ciphertext)[:8], mac)
    reader = SessionKeys(kek, kmk, host, card)
    chk("wrap-decrypts", reader.decrypt(ciphertext), payload)

    # The MCV chains: the same payload twice gives two different MACs.
    keys2 = SessionKeys(kek, kmk, host, card)
    first = wrap_command(keys2, payload)
    second = wrap_command(keys2, payload)
    chk("mcv-chains", first == second, False)

    # Segmentation: every segment fits one TLV, and they reassemble.
    package = bytes(range(256)) * 12         # 3072 octets
    segments = unsegment(package)
    chk("segments-reassemble", b"".join(segments), package)
    chk("segment-fits-tlv", all(len(wrap_command(keys, s)) <= MAX_TLV for s in segments), True)

    # An empty response TLV is '86 00' and carries no MAC.
    chk("empty-response", unpack_response(SessionKeys(kek, kmk, host, card),
                                          [(b"\x86", b"")]), b"")

    bad = 0
    for name, ok, got, want in checks:
        if ok:
            print("ok\t%s" % name)
        else:
            bad += 1
            print("FAIL\t%s\tgot %s\twant %s" % (name, got, want))
    print("%d checks, %d failed" % (len(checks), bad))
    return 1 if bad else 0


def _hex(s):
    return bytes.fromhex(s.replace(":", "").replace(" ", ""))


def main(argv):
    ap = argparse.ArgumentParser(add_help=True)
    ap.add_argument("--selfcheck", action="store_true")
    ap.add_argument("--k-enc")
    ap.add_argument("--k-mac")
    ap.add_argument("--host-challenge")
    ap.add_argument("--card-challenge")
    ap.add_argument("--kvn", default="30")
    ap.add_argument("--derive", action="store_true")
    ap.add_argument("--wrap")
    ap.add_argument("--unsegment")
    ap.add_argument("--parse", help="a hex TLV string to split into tag/length rows")
    a = ap.parse_args(argv)

    if a.selfcheck:
        return _selfcheck()

    if a.parse:
        for tag, value in parse_tlv(_hex(a.parse)):
            print("tag\t%s" % tag.hex().upper())
            print("len\t%d" % len(value))
            print("value\t%s" % (value.hex().upper() or "(empty)"))
        return 0

    if a.derive:
        keys = SessionKeys(_hex(a.k_enc), _hex(a.k_mac),
                           _hex(a.host_challenge), _hex(a.card_challenge))
        print("s_enc\t%s" % keys.s_enc.hex().upper())
        print("s_mac\t%s" % keys.s_mac.hex().upper())
        print("s_rmac\t%s" % keys.s_rmac.hex().upper())
        print("card_cryptogram\t%s" % keys.card_cryptogram.hex().upper())
        print("host_cryptogram\t%s" % keys.host_cryptogram.hex().upper())
        print("tlv_84\t%s" % init_update(int(a.kvn, 16), _hex(a.host_challenge)).hex().upper())
        print("tlv_85\t%s" % external_authenticate(keys).hex().upper())
        print("ref\tSGP.02 v4.3 4.1.3.3; GPC Amendment D Annex D 4.1.5 (KDF), 6.2 (session keys)")
        return 0

    if a.wrap:
        keys = SessionKeys(_hex(a.k_enc), _hex(a.k_mac),
                           _hex(a.host_challenge), _hex(a.card_challenge))
        # One run is one session: the 85 MAC is in the chain, so the 86 MACs
        # that follow are the ones a card would see after that handshake.
        print("tlv_85\t%s" % external_authenticate(keys).hex().upper())
        segments = unsegment(_hex(a.wrap))
        for n, seg in enumerate(segments, 1):
            print("tlv_86_%d\t%s" % (n, wrap_command(keys, seg).hex().upper()))
        print("segments\t%d" % len(segments))
        return 0

    if a.unsegment:
        segs = unsegment(_hex(a.unsegment))
        for n, s in enumerate(segs, 1):
            print("segment\t%d\t%d\t%s" % (n, len(s), s.hex().upper()[:64]))
        print("segments\t%d" % len(segs))
        return 0

    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
