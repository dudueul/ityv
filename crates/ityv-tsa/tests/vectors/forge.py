#!/usr/bin/env python3
"""Helpers for make.sh: describe a token, and craft the forged variants.

Standard library only. Run with `python3 -I`.

    forge.py describe TOKEN EMPTY_CONFIG
        Prints the token's fields as `openssl ts -reply -text` reports them,
        as `key=value` words for manifest.txt: time (Unix seconds), nanos,
        serial (hex), policy (dotted), nonce (hex or -), accuracy
        (seconds,millis,micros or -), ordering (yes/no). OpenSSL is the
        reference here, independent of the crate under test.

    forge.py forge KEY DIGEST TOKEN CERT EKU_CERT OUTDIR
        Writes forged-*.tst into OUTDIR: TOKEN (made by `openssl ts` with
        KEY, DIGEST and the certificate CERT) with one change each. Every
        variant whose change touches signed bytes is re-signed with KEY
        (`openssl dgst -sign`) after the message digest is recomputed, so
        the change under test is the only defect. EKU_CERT is a DER
        certificate for the same key whose extended key usage is not
        critical.
"""

import calendar
import hashlib
import subprocess
import sys
import time

# --- DER ---------------------------------------------------------------


def encode_length(n):
    if n < 0x80:
        return bytes([n])
    out = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(out)]) + out


class Node:
    """One DER element. Constructed elements keep their children; `raw`
    overrides the encoding (for deliberately non-canonical bytes)."""

    def __init__(self, tag, value=b"", children=None, raw=None):
        self.tag = tag
        self.value = value
        self.children = children
        self.raw = raw

    def encode(self):
        if self.raw is not None:
            return self.raw
        if self.children is not None:
            content = b"".join(child.encode() for child in self.children)
        else:
            content = self.value
        return bytes([self.tag]) + encode_length(len(content)) + content


def decode_one(data, at=0):
    tag = data[at]
    first = data[at + 1]
    if first < 0x80:
        length, start = first, at + 2
    else:
        count = first & 0x7F
        length = int.from_bytes(data[at + 2 : at + 2 + count], "big")
        start = at + 2 + count
    end = start + length
    value = data[start:end]
    if tag & 0x20:
        children, i = [], 0
        while i < len(value):
            child, i = decode_one(value, i)
            children.append(child)
        return Node(tag, children=children), end
    return Node(tag, value=value), end


def decode(data):
    node, end = decode_one(data)
    assert end == len(data)
    return node


def oid(dotted):
    arcs = [int(a) for a in dotted.split(".")]
    out = bytearray([40 * arcs[0] + arcs[1]])
    for arc in arcs[2:]:
        chunk = [arc & 0x7F]
        arc >>= 7
        while arc:
            chunk.append(0x80 | (arc & 0x7F))
            arc >>= 7
        out.extend(reversed(chunk))
    return Node(0x06, bytes(out))


def seq(*children):
    return Node(0x30, children=list(children))


def der_sorted(children):
    return sorted(children, key=lambda child: child.encode())


OID_CONTENT_TYPE = oid("1.2.840.113549.1.9.3").value
OID_MESSAGE_DIGEST = oid("1.2.840.113549.1.9.4").value
OID_SIGNING_CERT_V2 = oid("1.2.840.113549.1.9.16.2.47").value

# --- describe ----------------------------------------------------------


def describe(token, empty_config):
    text = subprocess.run(
        ["openssl", "ts", "-reply", "-config", empty_config, "-in", token,
         "-token_in", "-text"],
        check=True, capture_output=True, text=True).stdout
    fields = {}
    for line in text.splitlines():
        if ": " in line:
            key, value = line.split(": ", 1)
            fields[key.strip()] = value.strip()
    # "Nov  4 13:04:07.861 2026 GMT"
    month, day, clock, year, zone = fields["Time stamp"].split()
    assert zone == "GMT"
    whole, _, fraction = clock.partition(".")
    seconds = calendar.timegm(time.strptime(
        f"{month} {day} {whole} {year}", "%b %d %H:%M:%S %Y"))
    nanos = int((fraction + "000000000")[:9]) if fraction else 0

    def hex_of(value):
        if value == "unspecified":
            return "-"
        assert value.startswith("0x"), value
        digits = value[2:].lower()
        return digits if len(digits) % 2 == 0 else "0" + digits

    accuracy = fields["Accuracy"]
    if accuracy == "unspecified":
        accuracy_word = "-"
    else:
        parts = {}
        for part in accuracy.split(", "):
            number, unit = part.split()
            if number != "unspecified":
                parts[unit] = int(number, 16) if number.startswith("0x") else int(number)
        accuracy_word = "{},{},{}".format(parts.get("seconds", 0),
                                          parts.get("millis", 0),
                                          parts.get("micros", 0))
    serial = hex_of(fields["Serial number"]).lstrip("0") or "00"
    if len(serial) % 2:
        serial = "0" + serial
    print(f"time={seconds} nanos={nanos} serial={serial} "
          f"policy={fields['Policy OID']} nonce={hex_of(fields['Nonce'])} "
          f"accuracy={accuracy_word} ordering={fields['Ordering']}")


# --- forge -------------------------------------------------------------


class Token:
    """The parts of a token, as editable nodes."""

    def __init__(self, data):
        self.root = decode(data)
        self.signed_data = self.root.children[1].children[0]
        parts = self.signed_data.children
        self.encapsulated = parts[2]
        self.certificates = parts[3] if parts[3].tag == 0xA0 else None
        self.signer_infos = parts[-1]
        self.signer = self.signer_infos.children[0]
        self.tst = decode(self.encapsulated.children[1].children[0].value)

    def attributes(self):
        return self.signer.children[3].children

    def attribute(self, attribute_oid):
        for attribute in self.attributes():
            if attribute.children[0].value == attribute_oid:
                return attribute
        raise KeyError(attribute_oid)

    def set_attributes(self, attributes):
        self.signer.children[3].children = attributes

    def ess_cert_id(self):
        signing_certificate = self.attribute(OID_SIGNING_CERT_V2).children[1].children[0]
        return signing_certificate.children[0].children[0]

    def store_tst(self, digest):
        tst_bytes = self.tst.encode()
        self.encapsulated.children[1].children[0].value = tst_bytes
        digest_attribute = self.attribute(OID_MESSAGE_DIGEST)
        digest_attribute.children[1].children[0].value = hashlib.new(digest, tst_bytes).digest()

    def sign(self, key, digest):
        signed = Node(0x31, children=self.attributes()).encode()
        signature = subprocess.run(
            ["openssl", "dgst", "-" + digest, "-sign", key],
            input=signed, check=True, capture_output=True).stdout
        self.signer.children[5].value = signature

    def encode(self):
        return self.root.encode()


def forge(key, digest, token_path, cert_path, eku_cert_path, outdir):
    original = open(token_path, "rb").read()
    certificate = open(cert_path, "rb").read()
    eku_certificate = open(eku_cert_path, "rb").read()
    cert_node = decode(certificate)
    tbs = cert_node.children[0]
    issuer, serial = tbs.children[3], tbs.children[1]
    outputs = {}

    def variant(name, edit, tst=False, resign=True):
        token = Token(original)
        edit(token)
        if tst:
            token.store_tst(digest)
        if resign:
            token.sign(key, digest)
        outputs[name] = token.encode()

    # Signed attributes.
    variant("forged-no-ess", lambda t: t.set_attributes(
        [a for a in t.attributes() if a.children[0].value != OID_SIGNING_CERT_V2]))

    def flip_ess(t):
        cert_hash = t.ess_cert_id().children[0]
        cert_hash.value = bytes([cert_hash.value[0] ^ 1]) + cert_hash.value[1:]
    variant("forged-ess-hash", flip_ess)

    def explicit_sha256(t):
        t.ess_cert_id().children.insert(0, seq(oid("2.16.840.1.101.3.4.2.1")))
        t.set_attributes(der_sorted(t.attributes()))
    variant("forged-ess-default", explicit_sha256)

    def issuer_serial(serial_bytes):
        def edit(t):
            names = seq(Node(0xA4, children=[issuer]))
            t.ess_cert_id().children.append(seq(names, Node(0x02, serial_bytes)))
            t.set_attributes(der_sorted(t.attributes()))
        return edit
    variant("forged-ess-issuer-ok", issuer_serial(serial.value))
    wrong = (int.from_bytes(serial.value, "big") ^ 1).to_bytes(len(serial.value), "big")
    variant("forged-ess-issuer-bad", issuer_serial(wrong))

    def content_type_data(t):
        t.attribute(OID_CONTENT_TYPE).children[1].children[0] = oid("1.2.840.113549.1.7.1")
        t.set_attributes(der_sorted(t.attributes()))
    variant("forged-content-type", content_type_data)

    variant("forged-attrs-unsorted",
            lambda t: t.set_attributes(list(reversed(t.attributes()))))

    def unknown_attribute(t):
        extra = seq(oid("1.2.3.4.5.6"), Node(0x31, children=[Node(0x0C, b"ityv")]))
        t.set_attributes(der_sorted(t.attributes() + [extra]))
    variant("forged-unknown-attr", unknown_attribute)

    # TSTInfo content (each re-signed after the message digest is redone).
    def tst_edit(name, edit):
        variant(name, lambda t: edit(t.tst), tst=True)

    def critical(flag):
        def edit(tst):
            parts = [oid("1.2.3.4.99")]
            if flag:
                parts.append(Node(0x01, b"\xff"))
            parts.append(Node(0x04, b"\x05\x00"))
            tst.children.append(Node(0xA1, children=[seq(*parts)]))
        return edit
    tst_edit("forged-critical-ext", critical(True))
    tst_edit("forged-noncritical-ext", critical(False))

    def ordering_index(tst):
        for i, child in enumerate(tst.children):
            if child.tag == 0x01:
                return i
        raise KeyError("ordering")

    tst_edit("forged-bool-01", lambda tst: tst.children.__setitem__(
        ordering_index(tst), Node(0x01, raw=b"\x01\x01\x01")))
    tst_edit("forged-ordering-false", lambda tst: tst.children.__setitem__(
        ordering_index(tst), Node(0x01, b"\x00")))
    tst_edit("forged-int-nonminimal", lambda tst: tst.children.__setitem__(
        3, Node(0x02, raw=b"\x02" + bytes([len(tst.children[3].value) + 1]) + b"\x00"
                + tst.children[3].value)))

    def long_imprint_length(tst):
        imprint = tst.children[2]
        content = b"".join(child.encode() for child in imprint.children)
        assert len(content) < 0x80
        tst.children[2] = Node(0x30, raw=b"\x30\x81" + bytes([len(content)]) + content)
    tst_edit("forged-len-nonminimal", long_imprint_length)

    tst_edit("forged-tst-version", lambda tst: tst.children.__setitem__(0, Node(0x02, b"\x02")))

    def gen_time(text):
        return lambda tst: tst.children.__setitem__(4, Node(0x18, text.encode()))
    original_time = Token(original).tst.children[4].value.decode()
    base = original_time.split(".")[0].rstrip("Z")
    tst_edit("forged-time-trailing-zero", gen_time(base + ".50Z"))
    tst_edit("forged-outside-validity", gen_time("19990101000000Z"))

    def other_tsa_name(tst):
        name = seq(Node(0x31, children=[seq(oid("2.5.4.3"), Node(0x0C, b"another TSA"))]))
        for i, child in enumerate(tst.children):
            if child.tag == 0xA0:
                tst.children[i] = Node(0xA0, children=[Node(0xA4, children=[name])])
                return
        raise KeyError("tsa")
    tst_edit("forged-tsa-name", other_tsa_name)

    # The signer's certificate: the same key and name, extended key usage
    # not critical.
    def eku_noncritical(t):
        t.certificates.children = [decode(eku_certificate)]
        eku_tbs = decode(eku_certificate).children[0]
        t.signer.children[1] = seq(eku_tbs.children[3], eku_tbs.children[1])
        t.ess_cert_id().children[0].value = hashlib.sha256(eku_certificate).digest()
    variant("forged-eku-noncritical", eku_noncritical)

    # Unsigned parts: no re-signing needed.
    def sid_serial(t):
        sid_serial_node = t.signer.children[1].children[1]
        sid_serial_node.value = wrong
    variant("forged-sid-serial", sid_serial, resign=False)

    def algorithm(dotted):
        def edit(t):
            t.signer.children[4] = seq(oid(dotted), Node(0x05))
        return edit
    variant("forged-named-rsa-alg", algorithm("1.2.840.113549.1.1.12"), resign=False)
    variant("forged-alg-mismatch", algorithm("1.2.840.113549.1.1.11"), resign=False)

    # RSA boundaries: the signature as long as the modulus but equal to it
    # (s >= n), and one octet short.
    spki = tbs.children[6]
    modulus = decode(spki.children[1].value[1:]).children[0].value.lstrip(b"\x00")

    def signature_value(value_of):
        def edit(t):
            t.signer.children[5].value = value_of(t.signer.children[5].value)
        return edit
    variant("forged-rsa-sig-modulus", signature_value(lambda s: modulus), resign=False)
    variant("forged-rsa-sig-short", signature_value(lambda s: s[1:]), resign=False)

    variant("forged-two-signers", lambda t: t.signer_infos.children.append(
        decode(t.signer.encode())), resign=False)
    variant("forged-crls", lambda t: t.signed_data.children.insert(
        len(t.signed_data.children) - 1, Node(0xA1, children=[])), resign=False)
    variant("forged-detached", lambda t: t.encapsulated.children.pop(), resign=False)

    for name, data in outputs.items():
        with open(f"{outdir}/{name}.tst", "wb") as out:
            out.write(data)


def main(argv):
    if argv[1:2] == ["describe"] and len(argv) == 4:
        describe(argv[2], argv[3])
    elif argv[1:2] == ["forge"] and len(argv) == 8:
        forge(*argv[2:8])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
