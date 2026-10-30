"""Creates a certificate for each agent in the register.

The private key is written to mission-control/agents/certs/ and never leaves this
computer. Only the public certificate (jml/agents/<NAME>.cer) is copied to the
domain controller, where Register-OrbitAgents.ps1 attaches it to the agent's
identity in Entra ID. No passwords or client secrets anywhere.

    python agents/make_certs.py            # all agents in jml/config/agents.json
    python agents/make_certs.py HERMES     # just one
    python agents/make_certs.py --force    # replace existing certificates
"""
import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

AGENTS_DIR = Path(__file__).resolve().parent
REPO = AGENTS_DIR.parents[1]
REGISTER = REPO / "jml" / "config" / "agents.json"
PRIVATE_DIR = AGENTS_DIR / "certs"
PUBLIC_DIR = REPO / "jml" / "agents"


def make(name, force):
    key_path = PRIVATE_DIR / f"{name}.key.pem"
    cer_path = PUBLIC_DIR / f"{name}.cer"
    if key_path.exists() and cer_path.exists() and not force:
        der = cer_path.read_bytes()
        print(f"  {name:<7} exists       thumbprint {hashlib.sha1(der).hexdigest().upper()}")
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"{name} agent - Meridian Orbital")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=180))
            .sign(key, hashes.SHA256()))
    PRIVATE_DIR.mkdir(exist_ok=True)
    PUBLIC_DIR.mkdir(exist_ok=True)
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    der = cert.public_bytes(serialization.Encoding.DER)
    cer_path.write_bytes(der)
    print(f"  {name:<7} created      thumbprint {hashlib.sha1(der).hexdigest().upper()}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("names", nargs="*", help="agent names (default: every agent in the register)")
    parser.add_argument("--force", action="store_true", help="replace existing certificates")
    args = parser.parse_args()
    known = [a["name"] for a in json.loads(REGISTER.read_text(encoding="utf-8-sig"))["agents"]]
    names = [n.upper() for n in args.names] or known
    unknown = [n for n in names if n not in known]
    if unknown:
        sys.exit(f"Not in the agent register: {', '.join(unknown)}")
    print("Agent certificates (private keys stay in mission-control\\agents\\certs):")
    for name in names:
        make(name, args.force)
    print(f"\nNext: copy the .cer files in {PUBLIC_DIR} to the same folder on the domain controller.")


if __name__ == "__main__":
    main()
