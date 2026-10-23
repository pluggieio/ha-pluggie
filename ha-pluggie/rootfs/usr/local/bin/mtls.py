#!/usr/local/bin/python
"""Client certificate (mTLS) management for the Pluggie nginx HTTPS server.

CLI:
    mtls.py render [--off]   write nginx snippets from state, print the mode
    mtls.py disable          persist mode off, render, print the mode
"""

import base64
import contextlib
import datetime
import fcntl
import json
import logging
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DATA_DIR = "/data"
MTLS_DIR = "/data/mtls"
OPTIONS_FILE = "/data/pluggie.json"
MOUNTINFO_FILE = "/proc/self/mountinfo"
NGINX_MAP_FILE = "/etc/nginx/http.d/pluggie-mtls-map.conf"
NGINX_SNIPPET_DIR = "/etc/nginx/pluggie-mtls"
MTLS_LOG_FILE = "/var/log/nginx/pluggie_mtls.log"
LOG_TRUNCATE_BYTES = 256 * 1024

CA_KEY = "ca.key"
CA_CERT = "ca.crt"
STATE_FILE = "state.json"
LAST_SEEN_FILE = "last_seen.json"
LOCK_FILE = ".lock"

MODES = ("off", "test", "on")
# Why the mode was last changed; reported with mode off
REASONS = ("user", "reset", "remote", "state_missing", "error")
CA_DAYS = 3650
CLIENT_DAYS = 1825
CLOCK_SKEW = datetime.timedelta(minutes=5)
PASSWORD_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
PASSWORD_LENGTH = 16

STORAGE_ERROR = (
    "Client certificates cannot be turned on: /data is not a mounted "
    "directory, so the certificates would be lost when the container is "
    "recreated. Mount a host directory on /data and restart the container.")
CA_KEY_MISSING = (
    "The private key of the certificate authority is missing, so no device "
    "certificate can be issued. Restore a backup of the app, or use \"Delete "
    "all certificates\" and set up client certificates again.")

_NAME_RE = re.compile(r"\A[A-Za-z0-9 ._-]{1,64}\Z")
_ID_RE = re.compile(r"\A[0-9a-f]{16}\Z")
_FP_RE = re.compile(r"\A[0-9a-f]{40}\Z")


class MtlsError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def _path(name):
    return os.path.join(MTLS_DIR, name)


def _now():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def _iso(dt):
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ensure_dir():
    os.makedirs(MTLS_DIR, mode=0o700, exist_ok=True)


def _atomic_write(path, data, mode=0o644):
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def _write_json(name, obj):
    _atomic_write(_path(name), (json.dumps(obj, indent=2) + "\n").encode())


def _read_json(name, default):
    try:
        with open(_path(name), "r") as f:
            return json.load(f)
    except FileNotFoundError:
        return default
    except (OSError, ValueError) as exc:
        logging.warning(f"mTLS: cannot read {name}: {exc}")
        return default


@contextlib.contextmanager
def locked():
    _ensure_dir()
    with open(_path(LOCK_FILE), "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def validate_name(name):
    if not isinstance(name, str):
        raise MtlsError(400, "Device name is required")
    name = name.strip(" ")
    if not _NAME_RE.match(name):
        raise MtlsError(
            400,
            "Device name must be 1-64 characters: letters, digits, "
            "spaces, dots, underscores or dashes",
        )
    return name


def generate_password():
    return "".join(
        secrets.choice(PASSWORD_ALPHABET) for _ in range(PASSWORD_LENGTH)
    )


def fingerprint(cert):
    return cert.fingerprint(hashes.SHA1()).hex()


def data_is_persistent():
    """False when /data of the Docker edition is not a mount: its files
    live in the container layer and are lost when the container is
    recreated. Home Assistant always mounts /data."""
    if os.environ.get("SUPERVISOR_TOKEN"):
        return True
    try:
        with open(MOUNTINFO_FILE, "r") as f:
            for line in f:
                fields = line.split()
                if len(fields) > 4 and fields[4] == DATA_DIR:
                    return True
    except OSError:
        return True
    return False


def load_state():
    state = _read_json(STATE_FILE, None)
    if not isinstance(state, dict):
        return {"mode": "off", "clients": []}
    if state.get("mode") not in MODES:
        state["mode"] = "off"
    clients = state.get("clients")
    state["clients"] = [
        c for c in clients if isinstance(c, dict)
    ] if isinstance(clients, list) else []
    return state


def save_state(state):
    _write_json(STATE_FILE, state)


def _hostname():
    try:
        with open(OPTIONS_FILE, "r") as f:
            host = json.load(f).get("pluggie_config", {}).get("hostname")
        if isinstance(host, str) and host.strip():
            return host.strip()
    except (OSError, ValueError, AttributeError):
        pass
    return socket.gethostname()


def load_ca_cert():
    try:
        with open(_path(CA_CERT), "rb") as f:
            return x509.load_pem_x509_certificate(f.read())
    except FileNotFoundError:
        return None


def load_ca():
    cert = load_ca_cert()
    if cert is None:
        return None
    try:
        with open(_path(CA_KEY), "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
    except FileNotFoundError:
        raise MtlsError(409, CA_KEY_MISSING)
    return key, cert


def create_ca():
    key = ec.generate_private_key(ec.SECP256R1())
    cn = f"Pluggie client CA {_hostname()}"[:64].strip()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - CLOCK_SKEW)
        .not_valid_after(now + datetime.timedelta(days=CA_DAYS))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False),
            critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False)
        .sign(key, hashes.SHA256())
    )
    _ensure_dir()
    _atomic_write(
        _path(CA_KEY),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()),
        mode=0o600)
    _atomic_write(
        _path(CA_CERT), cert.public_bytes(serialization.Encoding.PEM))
    return key, cert


def issue_certificate(ca_key, ca_cert, name):
    """Return (cert, p12_bytes, password); the private key exists only here."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - CLOCK_SKEW)
        .not_valid_after(now + datetime.timedelta(days=CLIENT_DAYS))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False),
            critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()),
            critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    password = generate_password()
    # Legacy PBES1/3DES + SHA-1 MAC: the only PKCS#12 flavour Android, iOS
    # and macOS all import.
    encryption = (
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(2048)
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
        .hmac_hash(hashes.SHA1())
        .build(password.encode())
    )
    p12 = pkcs12.serialize_key_and_certificates(
        name.encode(), key, cert, [ca_cert], encryption)
    return cert, p12, password


def state_missing_locally():
    """Mode test/on recorded but the certificate authority is gone."""
    state = _read_json(STATE_FILE, None)
    return (isinstance(state, dict) and state.get("mode") in ("test", "on")
            and not os.path.isfile(_path(CA_CERT)))


def off_reason():
    """Why the effective mode is off, as reported to the apiserver."""
    state = _read_json(STATE_FILE, None)
    if not isinstance(state, dict) or state_missing_locally():
        return "state_missing"
    reason = state.get("reason")
    return reason if reason in REASONS else None


def effective_mode(state):
    if state["mode"] != "off" and os.path.isfile(_path(CA_CERT)):
        return state["mode"]
    return "off"


def active_fingerprints(state):
    return sorted({
        c.get("fingerprint") for c in state["clients"]
        if not c.get("revoked") and _FP_RE.match(str(c.get("fingerprint")))
    })


def render(state, force_off=False):
    """Write the nginx snippets for the given state; return the mode used."""
    mode = "off" if force_off else effective_mode(state)

    map_lines = [
        'map "$ssl_client_verify:$ssl_client_fingerprint" $pluggie_mtls_ok {',
        "    default 0;",
    ]
    if mode != "off":
        map_lines += [f'    "SUCCESS:{fp}" 1;' for fp in active_fingerprints(state)]
    map_lines += [
        "}",
        "log_format pluggie_mtls '$time_iso8601 $ssl_client_fingerprint';",
    ]

    if mode == "off":
        server_lines = ["access_log off;"]
    else:
        server_lines = [
            f"ssl_client_certificate {_path(CA_CERT)};",
            "ssl_verify_client optional;",
            "ssl_verify_depth 1;",
            f"access_log {MTLS_LOG_FILE} pluggie_mtls if=$pluggie_mtls_ok;",
        ]
    if mode == "test":
        # 495 (certificate fails verification) ends the request before any
        # location; Test mode never blocks, so continue in location /
        server_lines += [
            "error_page 495 496 = @pluggie_mtls_test;",
            "location @pluggie_mtls_test {",
            "    rewrite ^ $uri last;",
            "}",
        ]
    elif mode == "on":
        server_lines += [
            # 495/496 are never produced by the upstream, so HA's own 403
            # (ip_ban) is not replaced by this page.
            "error_page 495 496 =403 /mtls.html;",
            "location = /mtls.html {",
            "    root /usr/local/www;",
            "    internal;",
            "}",
        ]

    location_lines = []
    if mode == "on":
        location_lines = ["if ($pluggie_mtls_ok = 0) {", "    return 496;", "}"]

    os.makedirs(NGINX_SNIPPET_DIR, exist_ok=True)
    for path, lines in (
        (NGINX_MAP_FILE, map_lines),
        (os.path.join(NGINX_SNIPPET_DIR, "server.conf"), server_lines),
        (os.path.join(NGINX_SNIPPET_DIR, "location.conf"), location_lines),
    ):
        _atomic_write(path, "".join(f"{line}\n" for line in lines).encode())
    return mode


def _parse_log_time(value):
    try:
        dt = datetime.datetime.fromisoformat(value)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=datetime.timezone.utc)
    return _iso(dt)


def merge_log():
    """Fold the nginx mTLS log into last_seen.json; return the mapping."""
    last_seen = _read_json(LAST_SEEN_FILE, {})
    if not isinstance(last_seen, dict):
        last_seen = {}
    try:
        with open(MTLS_LOG_FILE, "r", errors="replace") as f:
            lines = f.readlines()
    except FileNotFoundError:
        return last_seen

    changed = False
    for line in lines:
        parts = line.split()
        if len(parts) != 2 or not _FP_RE.match(parts[1]):
            continue
        seen = _parse_log_time(parts[0])
        if seen and last_seen.get(parts[1], "") < seen:
            last_seen[parts[1]] = seen
            changed = True
    if changed:
        _write_json(LAST_SEEN_FILE, last_seen)
    with contextlib.suppress(OSError):
        if os.path.getsize(MTLS_LOG_FILE) > LOG_TRUNCATE_BYTES:
            os.truncate(MTLS_LOG_FILE, 0)
    return last_seen


def _is_active(client, now_iso):
    return not client.get("revoked") and client.get("not_after", "") > now_iso


def can_enforce(state, last_seen, exclude_id=None):
    now_iso = _iso(_now())
    return any(
        _is_active(c, now_iso) and c.get("fingerprint") in last_seen
        and c.get("id") != exclude_id
        for c in state["clients"]
    )


def public_view(state, last_seen):
    ca_cert = load_ca_cert()
    ca = None
    if ca_cert is not None:
        ca = {
            "created": _iso(ca_cert.not_valid_before_utc + CLOCK_SKEW),
            "not_after": _iso(ca_cert.not_valid_after_utc),
        }
    return {
        "mode": effective_mode(state),
        "ca": ca,
        "clients": [
            {
                "id": c.get("id"),
                "name": c.get("name"),
                "created": c.get("created"),
                "not_after": c.get("not_after"),
                "revoked": bool(c.get("revoked")),
                "last_seen": last_seen.get(c.get("fingerprint")),
            }
            for c in state["clients"]
        ],
        "can_enforce": can_enforce(state, last_seen),
        "data_persistent": data_is_persistent(),
    }


def apply_nginx():
    test = subprocess.run(
        ["nginx", "-t", "-q"], capture_output=True, text=True, timeout=30)
    if test.returncode != 0:
        raise RuntimeError(f"nginx -t failed: {test.stderr.strip()}")
    # Same check as apply_config.sh; busybox "pgrep -x" misses nginx's
    # rewritten process title.
    running = subprocess.run(
        ["pgrep", "nginx"], capture_output=True, timeout=10)
    if running.returncode == 0:
        reload = subprocess.run(
            ["nginx", "-s", "reload"], capture_output=True, text=True,
            timeout=30)
        if reload.returncode != 0:
            raise RuntimeError(f"nginx reload failed: {reload.stderr.strip()}")


def _snapshot():
    snap = {}
    for name in (CA_KEY, CA_CERT, STATE_FILE, LAST_SEEN_FILE):
        try:
            with open(_path(name), "rb") as f:
                snap[name] = f.read()
        except FileNotFoundError:
            snap[name] = None
    return snap


def _restore(snap):
    for name, data in snap.items():
        if data is None:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(_path(name))
        else:
            _atomic_write(
                _path(name), data, mode=0o600 if name == CA_KEY else 0o644)


def _transaction(mutate):
    """Run mutate(state, last_seen) under the lock, then render and reload
    nginx; on failure restore the previous files and re-render."""
    with locked():
        last_seen = merge_log()
        snap = _snapshot()
        state = load_state()
        try:
            result = mutate(state, last_seen)
            render(load_state())
            apply_nginx()
        except MtlsError:
            _restore(snap)
            raise
        except Exception as exc:
            logging.error(f"mTLS: applying configuration failed: {exc}")
            _restore(snap)
            with contextlib.suppress(Exception):
                render(load_state())
            raise MtlsError(
                500, "Applying the nginx configuration failed, "
                     "the change was reverted") from exc
        return result


def get_status():
    with locked():
        last_seen = merge_log()
        return public_view(load_state(), last_seen)


def set_mode(mode, reason="user"):
    if mode not in MODES:
        raise MtlsError(400, "Mode must be off, test or on")
    if mode != "off" and not data_is_persistent():
        raise MtlsError(409, STORAGE_ERROR)

    def mutate(state, last_seen):
        old = effective_mode(state)
        if mode == "on" and not can_enforce(state, last_seen):
            raise MtlsError(
                409, "Enforce can be turned on only after a device has "
                     "connected with its certificate in Test mode")
        if mode != "off" and load_ca_cert() is None:
            create_ca()
        state["mode"] = mode
        state["reason"] = reason
        save_state(state)
        return old

    old = _transaction(mutate)
    logging.debug(f"USER_ACTIVITY: mtls_mode_changed old={old} new={mode}")
    return get_status()


def add_client(name):
    """Issue a client certificate; return (client_view, filename, p12, password)."""
    name = validate_name(name)

    def mutate(state, last_seen):
        folded = name.casefold()
        if any(not c.get("revoked") and str(c.get("name", "")).casefold() == folded
               for c in state["clients"]):
            raise MtlsError(409, "A device with this name already exists")
        ca = load_ca() or create_ca()
        cert, p12, password = issue_certificate(ca[0], ca[1], name)
        ids = {c.get("id") for c in state["clients"]}
        client_id = secrets.token_hex(8)
        while client_id in ids:
            client_id = secrets.token_hex(8)
        client = {
            "id": client_id,
            "name": name,
            "serial": format(cert.serial_number, "x"),
            "fingerprint": fingerprint(cert),
            "created": _iso(_now()),
            "not_after": _iso(cert.not_valid_after_utc),
            "revoked": False,
        }
        state["clients"].append(client)
        save_state(state)
        return client, p12, password

    client, p12, password = _transaction(mutate)
    logging.debug(
        f"USER_ACTIVITY: mtls_client_issued id={client['id']} "
        f"name={client['name']}")
    view = {
        "id": client["id"],
        "name": client["name"],
        "created": client["created"],
        "not_after": client["not_after"],
        "revoked": False,
        "last_seen": None,
    }
    filename = "pluggie-" + re.sub(r"[^A-Za-z0-9._-]", "-", name) + ".p12"
    return view, filename, p12, password


def revoke_client(client_id):
    if not isinstance(client_id, str) or not _ID_RE.match(client_id):
        raise MtlsError(404, "Device not found")

    def mutate(state, last_seen):
        client = next(
            (c for c in state["clients"] if c.get("id") == client_id), None)
        if client is None:
            raise MtlsError(404, "Device not found")
        if client.get("revoked"):
            return client
        if (effective_mode(state) == "on"
                and not can_enforce(state, last_seen, exclude_id=client_id)):
            raise MtlsError(
                409, "Enforce is on and this is the last device that has "
                     "connected; switch to Test or Off first")
        client["revoked"] = True
        save_state(state)
        return client

    client = _transaction(mutate)
    logging.debug(
        f"USER_ACTIVITY: mtls_client_revoked id={client['id']} "
        f"name={client.get('name')}")
    return get_status()


def reset(confirm):
    if confirm != "RESET":
        raise MtlsError(400, 'Confirmation "RESET" is required')

    def mutate(state, last_seen):
        for name in (CA_KEY, CA_CERT):
            with contextlib.suppress(FileNotFoundError):
                os.unlink(_path(name))
        save_state({"mode": "off", "clients": [], "reason": "reset"})
        _write_json(LAST_SEEN_FILE, {})
        with contextlib.suppress(OSError):
            os.truncate(MTLS_LOG_FILE, 0)

    _transaction(mutate)
    logging.debug("USER_ACTIVITY: mtls_reset")
    return get_status()


def p12_base64(p12):
    return base64.b64encode(p12).decode()


def _cli_render(force_off):
    if not os.path.isdir(MTLS_DIR):
        return render({"mode": "off", "clients": []}, force_off=True)
    with locked():
        return render(load_state(), force_off=force_off)


def _cli_disable():
    with locked():
        state = load_state()
        if state["mode"] != "off":
            state["mode"] = "off"
            state["reason"] = "error"
            save_state(state)
        return render(state)


def acknowledge_missing_state():
    """Record mode off for a state whose certificate authority is gone."""
    with locked():
        if state_missing_locally():
            state = load_state()
            state["mode"] = "off"
            state["reason"] = "state_missing"
            save_state(state)


def main(argv):
    if argv[:1] == ["render"] and argv[1:] in ([], ["--off"]):
        print(_cli_render(argv[1:] == ["--off"]))
        return 0
    if argv == ["disable"]:
        print(_cli_disable())
        return 0
    sys.stderr.write("usage: mtls.py render [--off] | disable\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
