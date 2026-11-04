#!/usr/bin/env python3
"""Helpers for make.sh: describe a token, and craft the forged variants.

Standard library only. Run with `python3 -I`.

    forge.py describe TOKEN EMPTY_CONFIG
        Prints the token's fields as `openssl ts -reply -text` reports them,
        as `key=value` words for manifest.txt: time (Unix seconds), nanos,
        serial (hex), policy (dotted), nonce (hex or -), accuracy
        (seconds,millis,micros or -), ordering (yes/no). OpenSSL is the
        reference here, independent of the crate under test.

    forge.py forge KEY DIGEST TOKEN CERT OUTDIR [NAME=OTHER_CERT ...]
        Writes forged-*.tst into OUTDIR: TOKEN (made by `openssl ts` with
        KEY, DIGEST and the certificate CERT) with one change each. Every
        variant whose change touches signed bytes is re-signed with KEY
        (`openssl dgst -sign`) after the message digest is recomputed, so
        the change under test is the only defect. Each NAME=OTHER_CERT (a
        DER certificate for the same key) gives forged-NAME.tst, which
        embeds that certificate instead.
"""

import calendar
import datetime
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


def forge(key, digest, token_path, cert_path, outdir, *embeds):
    original = open(token_path, "rb").read()
    certificate = open(cert_path, "rb").read()
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

    def issuer_serial(names, serial_bytes):
        def edit(t):
            t.ess_cert_id().children.append(seq(seq(*names), Node(0x02, serial_bytes)))
            t.set_attributes(der_sorted(t.attributes()))
        return edit
    directory = Node(0xA4, children=[issuer])
    variant("forged-ess-issuer-ok", issuer_serial([directory], serial.value))
    wrong = (int.from_bytes(serial.value, "big") ^ 1).to_bytes(len(serial.value), "big")
    variant("forged-ess-issuer-bad", issuer_serial([directory], wrong))
    # Names that are not exactly one directoryName name no certificate.
    variant("forged-ess-issuer-dns",
            issuer_serial([Node(0x82, b"tsa.example")], serial.value))
    variant("forged-ess-issuer-two", issuer_serial([directory, directory], serial.value))

    def duplicate_content_type(t):
        again = decode(t.attribute(OID_CONTENT_TYPE).encode())
        t.set_attributes(der_sorted(t.attributes() + [again]))
    variant("forged-duplicate-attr", duplicate_content_type)

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

    # Size limits: a 160-bit serial and a 256-bit nonce, and one octet more.
    def serial_value(value):
        return lambda tst: tst.children.__setitem__(3, Node(0x02, value))
    tst_edit("forged-serial-20", serial_value(b"\x00" + b"\xff" * 20))
    tst_edit("forged-serial-21", serial_value(b"\x01" + b"\x00" * 20))

    def nonce_value(value):
        def edit(tst):
            for i, child in enumerate(tst.children):
                if i > 4 and child.tag == 0x02:
                    tst.children[i] = Node(0x02, value)
                    return
            raise KeyError("nonce")
        return edit
    tst_edit("forged-nonce-32", nonce_value(b"\x00" + b"\xff" * 32))
    tst_edit("forged-nonce-33", nonce_value(b"\x01" + b"\x00" * 32))

    def gen_time(text):
        return lambda tst: tst.children.__setitem__(4, Node(0x18, text.encode()))
    original_time = Token(original).tst.children[4].value.decode()
    base = original_time.split(".")[0].rstrip("Z")
    tst_edit("forged-time-trailing-zero", gen_time(base + ".50Z"))
    tst_edit("forged-outside-validity", gen_time("19990101000000Z"))

    # The validity bounds of the certificate, which are inclusive.
    def moment(node):
        text = node.value.decode()
        if node.tag == 0x17:
            text = ("19" if int(text[:2]) >= 50 else "20") + text
        return datetime.datetime.strptime(text, "%Y%m%d%H%M%SZ")

    def generalized(when, fraction=""):
        return when.strftime("%Y%m%d%H%M%S") + fraction + "Z"
    not_before = moment(tbs.children[4].children[0])
    not_after = moment(tbs.children[4].children[1])
    second = datetime.timedelta(seconds=1)
    tst_edit("forged-time-not-before", gen_time(generalized(not_before)))
    tst_edit("forged-time-before-not-before", gen_time(generalized(not_before - second)))
    tst_edit("forged-time-not-after", gen_time(generalized(not_after)))
    tst_edit("forged-time-after-not-after", gen_time(generalized(not_after, ".5")))

    def other_tsa_name(tst):
        name = seq(Node(0x31, children=[seq(oid("2.5.4.3"), Node(0x0C, b"another TSA"))]))
        for i, child in enumerate(tst.children):
            if child.tag == 0xA0:
                tst.children[i] = Node(0xA0, children=[Node(0xA4, children=[name])])
                return
        raise KeyError("tsa")
    tst_edit("forged-tsa-name", other_tsa_name)

    # Other certificates for the same key and name (make.sh varies the
    # extensions): embedded, named by the signer identifier and ESS.
    def embed(other):
        def edit(t):
            node = decode(other)
            t.certificates.children = [node]
            t.signer.children[1] = seq(node.children[0].children[3], node.children[0].children[1])
            t.ess_cert_id().children[0].value = hashlib.sha256(other).digest()
        return edit
    for spec in embeds:
        name, path = spec.split("=", 1)
        variant(f"forged-{name}", embed(open(path, "rb").read()))

    # Unsigned parts: no re-signing needed.
    def sid_serial(t):
        sid_serial_node = t.signer.children[1].children[1]
        sid_serial_node.value = wrong
    variant("forged-sid-serial", sid_serial, resign=False)

    def sid_issuer_not_der(t):
        name = decode(t.signer.children[1].children[0].encode())
        name.children.append(Node(0x31, children=[seq(Node(0x01, raw=b"\x01\x01\x01"))]))
        t.signer.children[1].children[0] = name
    variant("forged-sid-issuer-der", sid_issuer_not_der, resign=False)

    # The signer named by subject key identifier (SignerInfo version 3).
    key_id = None
    for extension in tbs.children[7].children[0].children:
        if extension.children[0].value == oid("2.5.29.14").value:
            key_id = decode(extension.children[-1].value).value

    def signer_id(version, sid):
        def edit(t):
            t.signer.children[0] = Node(0x02, bytes([version]))
            if sid is not None:
                t.signer.children[1] = sid
        return edit
    variant("forged-sid-keyid", signer_id(3, Node(0x80, key_id)), resign=False)
    variant("forged-sid-keyid-bad",
            signer_id(3, Node(0x80, bytes([key_id[0] ^ 1]) + key_id[1:])), resign=False)
    variant("forged-sid-keyid-v1", signer_id(1, Node(0x80, key_id)), resign=False)
    variant("forged-sid-version3", signer_id(3, None), resign=False)

    # The certificate set: the limit of eight, and a choice that is not a
    # certificate (an empty [1] attribute certificate).
    def certificate_set(count, extra=None):
        def edit(t):
            t.certificates.children = [decode(certificate) for _ in range(count)]
            if extra is not None:
                t.certificates.children.append(extra)
        return edit
    variant("forged-eight-certs", certificate_set(8), resign=False)
    variant("forged-nine-certs", certificate_set(9), resign=False)
    variant("forged-cert-choice", certificate_set(1, Node(0xA1, children=[])), resign=False)

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
    elif argv[1:2] == ["forge"] and len(argv) >= 7:
        forge(*argv[2:])
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
