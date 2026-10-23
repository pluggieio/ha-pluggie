#!/usr/local/bin/python
"""
SSL Certificate Fingerprint Verification Module for Pluggie.

Periodically fetches the remote SSL certificate fingerprint via the public
internet (using DNS-over-HTTPS for secure hostname resolution) and compares
it with the locally stored Let's Encrypt certificate.  The goal is to detect
potential MITM attacks where a relay server might substitute its own
certificate.
"""

import hashlib
import json
import logging
import os
import socket
import ssl
import struct
import subprocess
import threading
import time

import requests

from logger import get_logger

OPTIONS_FILE = "/data/pluggie.json"
CERT_VERIFY_FILE = "/tmp/cert_verify.json"
STATE_FILE = "/etc/pluggie.state"
# Each probe is a TLS handshake through the tunnel, counted by the edge.
# The apiserver holds the tunnel counters during the probe (phase "start")
# and takes the probe bytes off before they are shown (phase "end").
# Hourly plus after events (start, reconnect, new certificate, hostname
# change)
VERIFY_INTERVAL = 3600
EVENT_MIN_GAP = 900
EVENT_DAILY_LIMIT = 8
# A probe that failed (e.g. during an outage) is repeated once after this
ERROR_RETRY = 1800
INITIAL_DELAY = 120  # 2 minutes after startup
TRIGGER_FILE = "/tmp/cert_verify_trigger"
CERT_BUSY_FILE = "/tmp/pluggie_cert_busy"
CERT_BUSY_MAX_AGE = 600  # ignore stale marker
CONFIG_REFRESH_TRIGGER = "/tmp/pluggie_config_refresh"
CONFIG_CHECK_INTERVAL = 900
# Unchanged results are reported at most daily; changes at once
REPORT_STATE_FILE = "/tmp/cert_verify_reported.json"
REPORT_MAX_AGE = 86400
SETTINGS_CHANGED = "Tunnel settings changed, configuration is being refreshed"
# Tunnel bytes of probes not yet reported (credited by the apiserver);
# kept across restarts so a late report still corrects the counters
OVERHEAD_FILE = "/data/cert_verify_overhead.json"
# Wait after the probe socket closed so its last segments pass the edge
# before the report releases the hold
CLOSE_SETTLE = 1.0
# Retries of the closing report, all within the apiserver's hold (180 s)
END_REPORT_DELAYS = (0, 15, 45)
API_TIMEOUT = 10
PROBE_DEFERRED = "Check postponed, it will run again automatically"
# Tunnel side of a probe as the edge counts it: IP packets of the
# edge -> addon connection, both directions. Estimated from the probe's own
# TCP counters: payload + IPv4/TCP header with timestamps per segment,
# SYN options, the PROXY protocol line and the closing segments
# (calibrated on the dev edge: 7793 B counted, 7815 B estimated).
TUNNEL_HEADER_BYTES = 52
SYN_OPTION_BYTES = 16
PROXY_HEADER_BYTES = 56
CLOSE_SEGMENTS = 5
MAX_PROBE_BYTES = 16384
_TCP_INFO_LEN = 232

_wakeup_event = threading.Event()
_state_lock = threading.Lock()
_probe_times = {"last": None, "events": []}


def _load_doh_resolvers():
    """
    Load DoH resolver URLs from pluggie.json configuration.

    Falls back to a sensible default list when the config key is absent.

    Returns:
        A list of DoH server URL strings.
    """
    default_resolvers = [
        "https://1.1.1.1/dns-query",
        "https://8.8.8.8/dns-query",
    ]
    try:
        if os.path.isfile(OPTIONS_FILE):
            with open(OPTIONS_FILE, "r") as fh:
                options = json.load(fh)
            resolvers = options.get(
                "pluggie_config", {},
            ).get("doh_resolvers")
            if isinstance(resolvers, list) and resolvers:
                return resolvers
    except Exception as exc:
        logging.debug("Failed to load doh_resolvers from config: %s", exc)
    return default_resolvers


def _resolve_hostname_doh(hostname):
    """
    Resolve a hostname to an IPv4 address using DNS-over-HTTPS (DoH).

    Resolver URLs are read from pluggie_config.doh_resolvers in
    pluggie.json.  Falls back to Cloudflare + Google when the key is
    not present.

    Args:
        hostname: The hostname to resolve.

    Returns:
        The resolved IPv4 address string, or None on failure.
    """
    doh_servers = _load_doh_resolvers()

    for server in doh_servers:
        try:
            resp = requests.get(
                server,
                params={"name": hostname, "type": "A"},
                headers={"Accept": "application/dns-json"},
                timeout=10,
            )
            if resp.status_code != 200:
                continue

            data = resp.json()
            answers = data.get("Answer", [])
            for answer in answers:
                if answer.get("type") == 1:  # A record
                    ip_addr = answer.get("data")
                    if ip_addr:
                        logging.debug(
                            "DoH resolved %s -> %s via %s",
                            hostname, ip_addr, server,
                        )
                        return ip_addr

            # Handle CNAME chain - follow until we get an A record
            for answer in answers:
                if answer.get("type") == 5:  # CNAME
                    cname_target = answer.get("data", "").rstrip(".")
                    if cname_target:
                        return _resolve_hostname_doh(cname_target)

        except Exception as exc:
            logging.debug("DoH resolution failed via %s: %s", server, exc)
            continue

    logging.warning("DoH resolution failed for %s on all servers", hostname)
    return None


def _get_remote_cert_fingerprint(hostname, ip_addr, port=443):
    """
    Connect to *ip_addr* on *port* using TLS with SNI set to *hostname*
    and return the SHA-256 fingerprint of the peer certificate in DER form.

    Args:
        hostname: SNI hostname for the TLS handshake.
        ip_addr:  Resolved IP address to connect to.
        port:     Target port (default 443).

    Returns:
        A colon-separated SHA-256 fingerprint string, or None on error.
    """
    try:
        ctx = ssl.create_default_context()
        # We only want the fingerprint - don't verify the chain here
        # because the addon itself is the legitimate certificate holder.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip_addr, port), timeout=15) as raw:
            tls = ctx.wrap_socket(raw, server_hostname=hostname,
                                  do_handshake_on_connect=False)
            try:
                tls.do_handshake()
                der_cert = tls.getpeercert(binary_form=True)
                _settle(tls)
            finally:
                _record_probe(tls)
                tls.close()
            if not der_cert:
                logging.warning(
                    "No certificate received from %s (%s)",
                    hostname, ip_addr,
                )
                return None

            sha256 = hashlib.sha256(der_cert).hexdigest().upper()
            fingerprint = ":".join(
                sha256[i:i + 2] for i in range(0, len(sha256), 2)
            )
            logging.debug(
                "Remote cert fingerprint for %s: %s",
                hostname, fingerprint,
            )
            return fingerprint
    except Exception as exc:
        logging.warning(
            "Failed to get remote certificate from %s (%s:%d): %s",
            hostname, ip_addr, port, exc,
        )
        return None


def _tcp_info(sock):
    """(bytes out, bytes in, segments out, segments in, rtt us) or None."""
    try:
        info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO,
                               _TCP_INFO_LEN)
    except (OSError, AttributeError, ValueError):
        return None
    if len(info) < 144:
        return None
    rtt = struct.unpack_from("=I", info, 68)[0]
    bytes_acked, bytes_received = struct.unpack_from("=QQ", info, 120)
    segs_out, segs_in = struct.unpack_from("=II", info, 136)
    return bytes_acked, bytes_received, segs_out, segs_in, rtt


def _settle(sock):
    """Let the server's last handshake records (session tickets) arrive."""
    info = _tcp_info(sock)
    rtt = info[4] / 1e6 if info else 0.1
    time.sleep(min(1.0, max(0.2, 3 * rtt)))


def probe_tunnel_bytes(info):
    """Estimated tunnel bytes of one probe from its TCP counters."""
    if not info:
        return 0
    bytes_out, bytes_in, segs_out, segs_in, _ = info
    if not segs_in:
        return 0
    estimate = (bytes_out + bytes_in + PROXY_HEADER_BYTES
                + 2 * SYN_OPTION_BYTES
                + (segs_out + segs_in + CLOSE_SEGMENTS) * TUNNEL_HEADER_BYTES)
    return min(estimate, MAX_PROBE_BYTES)


def _record_probe(sock):
    _add_overhead(probe_tunnel_bytes(_tcp_info(sock)))


def _load_overhead():
    try:
        with open(OVERHEAD_FILE, "r") as fh:
            data = json.load(fh)
        value, probes = int(data.get("bytes", 0)), int(data.get("probes", 0))
        if value >= 0 and probes >= 0:
            return {"bytes": value, "probes": probes}
    except (OSError, ValueError, TypeError, AttributeError):
        pass
    return {"bytes": 0, "probes": 0}


def _save_overhead(data):
    try:
        tmp = OVERHEAD_FILE + ".tmp"
        with open(tmp, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp, OVERHEAD_FILE)
    except OSError as exc:
        logging.debug("Failed to save probe overhead: %s", exc)


def _add_overhead(value):
    if value <= 0:
        return
    with _state_lock:
        data = _load_overhead()
        data["bytes"] += value
        data["probes"] += 1
        _save_overhead(data)
    logging.debug("Certificate probe: about %d bytes through the tunnel",
                  value)


def pending_overhead():
    with _state_lock:
        return _load_overhead()


def _clear_overhead(sent):
    with _state_lock:
        data = _load_overhead()
        data["bytes"] = max(0, data["bytes"] - sent["bytes"])
        data["probes"] = max(0, data["probes"] - sent["probes"])
        _save_overhead(data)


def _cert_issuance_in_progress():
    """Return True while letsencrypt/run is issuing the certificate."""
    try:
        age = time.time() - os.path.getmtime(CERT_BUSY_FILE)
    except OSError:
        return False
    return age < CERT_BUSY_MAX_AGE


def _get_local_cert_fingerprint(hostname):
    """
    Read the local Let's Encrypt certificate and return its SHA-256
    fingerprint.

    The certificate path is derived from the standard certbot directory
    layout under the Pluggie SSL directory.

    Args:
        hostname: The hostname whose certificate to read.

    Returns:
        A colon-separated SHA-256 fingerprint string, or None on error.
    """
    # Determine Pluggie SSL directory
    if os.environ.get("SUPERVISOR_TOKEN"):
        pluggie_dir = "/ssl/pluggie"
    else:
        pluggie_dir = "/data"

    cert_path = os.path.join(
        pluggie_dir, "letsencrypt", "live", hostname, "cert.pem",
    )

    if not os.path.isfile(cert_path):
        # Certbot may use a numbered directory when certs are expanded
        live_dir = os.path.join(pluggie_dir, "letsencrypt", "live")
        if os.path.isdir(live_dir):
            for entry in sorted(os.listdir(live_dir), reverse=True):
                if entry.startswith(hostname):
                    candidate = os.path.join(live_dir, entry, "cert.pem")
                    if os.path.isfile(candidate):
                        cert_path = candidate
                        break

    if not os.path.isfile(cert_path):
        logging.warning("Local certificate not found at %s", cert_path)
        return None

    try:
        # Convert PEM to DER for fingerprinting
        result = subprocess.run(
            ["openssl", "x509", "-in", cert_path, "-outform", "DER"],
            capture_output=True,
            timeout=10,
        )
        if result.returncode != 0:
            logging.warning(
                "openssl x509 failed: %s",
                result.stderr.decode(errors="replace"),
            )
            return None

        der_bytes = result.stdout
        sha256 = hashlib.sha256(der_bytes).hexdigest().upper()
        fingerprint = ":".join(
            sha256[i:i + 2] for i in range(0, len(sha256), 2)
        )
        logging.debug(
            "Local cert fingerprint for %s: %s", hostname, fingerprint,
        )
        return fingerprint
    except Exception as exc:
        logging.warning("Failed to read local certificate: %s", exc)
        return None


def _settings_changed():
    """True when the tunnel settings changed in the Pluggie account, so a
    mismatch or unresolvable hostname is expected until the refresh."""
    if os.path.exists(CONFIG_REFRESH_TRIGGER):
        return True
    try:
        from get_config import check_remote_config
    except ImportError as exc:
        logging.debug("Config check unavailable: %s", exc)
        return False
    return check_remote_config(CONFIG_CHECK_INTERVAL) == "changed"


def _settings_changed_result(result):
    result["status"] = "pending"
    result["error"] = SETTINGS_CHANGED
    result["match"] = None
    return result


def _save_result(result):
    """Persist verification result to a JSON file for the API to read."""
    try:
        with open(CERT_VERIFY_FILE, "w") as fh:
            json.dump(result, fh, indent=2)
    except Exception as exc:
        logging.error("Failed to save cert verification result: %s", exc)


def run_verification():
    """
    Execute a single certificate fingerprint verification cycle.

    Returns:
        A dict with the verification result.
    """
    result = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "unknown",
        "local_fingerprint": None,
        "remote_fingerprint": None,
        "match": None,
        "hostname": None,
        "error": None,
        "cert_dir": None,
        "cert_hint": None,
    }
    probe = {"hold": None}
    session = _api_session()
    try:
        try:
            _verify(result, session, probe)
        except Exception as exc:
            result["status"] = "error"
            result["error"] = str(exc)
            logging.error("Certificate verification error: %s", exc)

        # Report result to API server; a held probe always closes its hold
        if probe["hold"] == "held":
            _finish_held_probe(result, session)
        elif (result["status"] in ("verified", "mismatch")
              and _report_due(result)):
            if _report_to_apiserver(result, session) == 200:
                _save_report_state(result)
    finally:
        session.close()
    return result


def _verify(result, session, probe):
    """The verification itself; fills *result*, sets probe["hold"]."""
    # Read hostname from pluggie.json
    if not os.path.isfile(OPTIONS_FILE):
        result["status"] = "error"
        result["error"] = "Options file not found"
        return result

    with open(OPTIONS_FILE, "r") as fh:
        options = json.load(fh)

    hostname = options.get("pluggie_config", {}).get("hostname")
    if not hostname:
        result["status"] = "error"
        result["error"] = "Hostname not configured"
        return result

    result["hostname"] = hostname

    # Check that addon is in a working state
    if os.path.isfile(STATE_FILE):
        with open(STATE_FILE, "r") as fh:
            state = fh.read().strip()
        if state not in ("enabled",):
            result["status"] = "skipped"
            result["error"] = (
                f"Addon state is '{state}', skipping verification"
            )
            return result

    # Local cert or nginx may not be ready yet
    if _cert_issuance_in_progress():
        result["status"] = "pending"
        result["error"] = "Certificate is being issued"
        return result

    # Step 1: resolve hostname via DoH
    ip_addr = _resolve_hostname_doh(hostname)
    if not ip_addr:
        if _settings_changed():
            return _settings_changed_result(result)
        result["status"] = "error"
        result["error"] = "Failed to resolve hostname via DoH"
        return result

    # Step 2: hold the tunnel counters, then get the remote certificate
    # fingerprint. Without the hold the probe would be counted, so it
    # waits for the next attempt.
    hold, retry_after = _start_probe(session)
    if hold is None:
        result["status"] = "deferred"
        result["error"] = PROBE_DEFERRED
        result["retry_after"] = retry_after
        return result
    probe["hold"] = hold
    # Always use port 443 - the public-facing HTTPS port on the
    # relay server.  pluggie_config.https_port is the *internal*
    # port behind WireGuard, not the public one.
    result["probed"] = True
    with _state_lock:
        _probe_times["last"] = time.monotonic()
    remote_fp = _get_remote_cert_fingerprint(hostname, ip_addr, 443)
    result["remote_fingerprint"] = remote_fp

    if not remote_fp:
        result["status"] = "error"
        result["error"] = "Failed to retrieve remote certificate"
        return result

    # Step 3: get local certificate fingerprint
    local_fp = _get_local_cert_fingerprint(hostname)
    result["local_fingerprint"] = local_fp

    # Store cert location hint for UI
    live_path = f"letsencrypt/live/{hostname}/"
    if os.environ.get("SUPERVISOR_TOKEN"):
        result["cert_dir"] = f"/ssl/pluggie/{live_path}"
        result["cert_hint"] = ""
    else:
        result["cert_dir"] = live_path
        result["cert_hint"] = "inside the volume mounted to /data in your container"

    if not local_fp:
        result["status"] = "error"
        result["error"] = "Failed to read local certificate"
        return result

    # Step 4: compare
    if local_fp != remote_fp and _settings_changed():
        return _settings_changed_result(result)
    result["match"] = (local_fp == remote_fp)
    result["status"] = "verified" if result["match"] else "mismatch"

    if result["match"]:
        logging.debug(
            "Certificate verification OK for %s - fingerprints match",
            hostname,
        )
    else:
        logging.warning(
            "Certificate MISMATCH for %s! "
            "Local: %s  Remote: %s - possible MITM!",
            hostname, local_fp, remote_fp,
        )
    return result


def _report_key(result):
    return [result.get(name) for name in (
        "hostname", "status", "local_fingerprint", "remote_fingerprint")]


def _report_due(result, now=None):
    """Report a changed result at once, an unchanged one once a day, and
    any result while probe traffic waits to be credited."""
    now = time.time() if now is None else now
    if pending_overhead()["probes"]:
        return True
    try:
        with open(REPORT_STATE_FILE, "r") as fh:
            last = json.load(fh)
        if last.get("key") != _report_key(result):
            return True
        return not 0 <= now - float(last.get("time", 0)) < REPORT_MAX_AGE
    except (OSError, ValueError, TypeError, AttributeError):
        return True


def _save_report_state(result, now=None):
    now = time.time() if now is None else now
    try:
        with open(REPORT_STATE_FILE, "w") as fh:
            json.dump({"key": _report_key(result), "time": now}, fh)
    except OSError as exc:
        logging.debug("Failed to save cert verify report state: %s", exc)


def _api_session():
    """One connection for the probe start, the report and its retries."""
    return requests.Session()


def _api_context():
    """(url, headers) of the cert-verify endpoint, or None without a key."""
    if not os.path.isfile(OPTIONS_FILE):
        return None
    with open(OPTIONS_FILE, "r") as fh:
        options = json.load(fh)

    access_key = options.get("configuration", {}).get("access_key")
    if not access_key or access_key == "XXXXX":
        return None

    api_server = options.get(
        "pluggie_config", {},
    ).get("apiserver", "api.pluggie.net")
    user_agent = options.get("user_agent", "Pluggie-Client")
    headers = {
        "Authorization": f"Bearer {access_key}",
        "User-Agent": user_agent,
        "Content-Type": "application/json",
    }
    return f"https://{api_server}/api/cert-verify", headers


def _start_probe(session):
    """Ask the apiserver to hold the tunnel counters for one probe.

    Returns ("held", 0) when the counters are held, ("legacy", 0) when the
    apiserver does not know holds (older version: probe as before), or
    (None, retry_after) when the probe has to wait (apiserver unreachable,
    probe refused).
    """
    try:
        context = _api_context()
    except (OSError, ValueError) as exc:
        logging.debug("Cannot read options for the probe hold: %s", exc)
        return None, ERROR_RETRY
    if context is None:
        return "legacy", 0
    url, headers = context
    try:
        resp = session.post(url, headers=headers, json={"phase": "start"},
                            timeout=API_TIMEOUT)
    except Exception as exc:
        logging.debug("Probe hold request failed: %s", exc)
        return None, ERROR_RETRY
    if resp.status_code == 200:
        return "held", 0
    if resp.status_code in (400, 404, 405):
        return "legacy", 0
    retry_after = ERROR_RETRY
    if resp.status_code == 429:
        try:
            retry_after = int(resp.json().get("retry_after", ERROR_RETRY))
        except (ValueError, TypeError, AttributeError):
            pass
    logging.debug("Probe hold refused: %d, retry in %d s",
                  resp.status_code, retry_after)
    return None, retry_after


def _finish_held_probe(result, session):
    """Close the probe hold: the report carries the probe bytes and, when
    due, the result. Retried within the hold; without it the apiserver
    releases the hold in full and a later report corrects the counters."""
    time.sleep(CLOSE_SETTLE)
    with_result = (result["status"] in ("verified", "mismatch")
                   and _report_due(result))
    for delay in END_REPORT_DELAYS:
        if delay:
            time.sleep(delay)
        code = _report_to_apiserver(result, session, phase="end",
                                    with_result=with_result)
        if code == 200:
            if with_result:
                _save_report_state(result)
            return True
        if code is not None and 400 <= code < 500:
            return False
    return False


def _report_to_apiserver(result, session=None, phase=None,
                         with_result=True):
    """
    Report certificate verification result to the Pluggie API server.

    The API server stores the result and sends email notification
    to the user if a mismatch is detected. Probe bytes not yet reported
    go with it.

    Args:
        result: Verification result dict.
        session: requests session (a new connection when None).
        phase: "end" closes the probe hold.
        with_result: False sends only the probe bytes (phase "end").

    Returns:
        The HTTP status code, or None when nothing could be sent.
    """
    try:
        context = _api_context()
        if context is None:
            return None
        api_url, headers = context

        payload = {}
        if with_result:
            payload.update({
                "status": result.get("status"),
                "local_fingerprint": result.get("local_fingerprint"),
                "remote_fingerprint": result.get("remote_fingerprint"),
                "match": result.get("match"),
                "timestamp": result.get("timestamp"),
            })
        if phase:
            payload["phase"] = phase
        overhead = pending_overhead()
        if overhead["probes"]:
            payload["overhead"] = overhead

        post = session.post if session is not None else requests.post
        resp = post(api_url, headers=headers, json=payload,
                    timeout=API_TIMEOUT)
        logging.debug(
            "Cert verify reported to apiserver: %d", resp.status_code,
        )
        if resp.status_code == 200 and overhead["probes"]:
            _clear_overhead(overhead)
        return resp.status_code
    except Exception as exc:
        logging.debug("Failed to report cert verify to apiserver: %s", exc)
    return None


def trigger_verification():
    """
    Signal the verification loop to run immediately.

    Called after a successful reconnect to skip the remaining sleep
    interval and run a fresh certificate check right away.
    """
    _wakeup_event.set()


def _take_trigger():
    """True when an event (reconnect, new certificate) asked for a check."""
    triggered = False
    if _wakeup_event.is_set():
        _wakeup_event.clear()
        triggered = True
    try:
        if os.path.exists(TRIGGER_FILE):
            os.remove(TRIGGER_FILE)
            triggered = True
    except OSError:
        pass
    return triggered


def event_probe_allowed(now):
    """True: probe now, False: wait for EVENT_MIN_GAP, None: daily event
    budget used up (the schedule covers it)."""
    with _state_lock:
        events = [t for t in _probe_times["events"] if now - t < 86400]
        _probe_times["events"] = events
        last = _probe_times["last"]
    if len(events) >= EVENT_DAILY_LIMIT:
        return None
    return last is None or now - last >= EVENT_MIN_GAP


def verification_step(state, now):
    """One scheduling decision; returns True when a check ran."""
    if _take_trigger():
        state["event"] = True
    last_run = state["last_run"]
    retry_at = state.get("retry_at")
    due = (last_run is None or now - last_run >= VERIFY_INTERVAL
           or (retry_at is not None and now >= retry_at))
    event = False
    if not due and state["event"]:
        allowed = event_probe_allowed(now)
        if allowed is None:
            state["event"] = False
        event = bool(allowed)
    if not (due or event):
        return False
    state["event"] = False
    state["last_run"] = now
    result = run_verification()
    if result.get("status") == "deferred":
        # No hold for the probe: keep the last result, try again later
        wait = result.get("retry_after") or ERROR_RETRY
        state["retry_at"] = now + min(ERROR_RETRY, max(60, wait))
        return True
    _save_result(result)
    if event and result.get("probed"):
        with _state_lock:
            _probe_times["events"].append(now)
    state["retry_at"] = None
    if result.get("status") in ("verified", "mismatch"):
        state["retried"] = False
    elif (result.get("probed") and result.get("status") == "error"
          and not state.get("retried")):
        state["retry_at"] = now + ERROR_RETRY
        state["retried"] = True
    return True


def verification_loop():
    """
    Background loop: a check every VERIFY_INTERVAL, and after events
    (_wakeup_event or TRIGGER_FILE written by shell scripts after a
    reconnect or a new certificate) at most every EVENT_MIN_GAP and
    EVENT_DAILY_LIMIT times a day. Intended to be started as a daemon
    thread from admin_api.py.
    """
    get_logger("cert_verify")
    logging.debug(
        "Certificate verification thread started (interval: %ds)",
        VERIFY_INTERVAL,
    )

    # Initial delay to let services fully start; honour early triggers.
    if not os.path.exists(TRIGGER_FILE):
        _wakeup_event.wait(timeout=INITIAL_DELAY)

    state = {"last_run": None, "event": False}
    while True:
        try:
            verification_step(state, time.monotonic())
        except Exception as exc:
            logging.error(
                "Unexpected error in verification loop: %s", exc,
            )
        _wakeup_event.wait(timeout=10)


def start_verification_thread():
    """Start the background verification thread (daemon)."""
    thread = threading.Thread(target=verification_loop, daemon=True)
    thread.name = "cert-verify"
    thread.start()
    return thread


def get_last_result():
    """
    Read and return the last verification result from disk.

    Returns:
        A dict with the last result, or a default 'pending' result.
    """
    if os.path.isfile(CERT_VERIFY_FILE):
        try:
            with open(CERT_VERIFY_FILE, "r") as fh:
                return json.load(fh)
        except Exception:
            pass

    return {
        "status": "pending",
        "local_fingerprint": None,
        "remote_fingerprint": None,
        "match": None,
        "hostname": None,
        "error": "Verification has not run yet",
    }
