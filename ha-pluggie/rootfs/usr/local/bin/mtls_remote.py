#!/usr/local/bin/python
"""Remote commands from the Pluggie apiserver and tunnel ownership proof.

Commands are fetched when the Pluggie endpoint rings the doorbell
(doorbell.py), after start or reconnect (get_config.py), when the mTLS mode
changed, and every 60 s while mTLS is on with an apiserver that announces
no doorbell.

CLI:
    mtls_remote.py poll   fetch and run pending commands when due
"""

import contextlib
import datetime
import fcntl
import json
import logging
import os
import re
import sys
import time

import requests

import mtls
from logger import setup_logging

OPTIONS_FILE = "/data/pluggie.json"
DEFAULT_APISERVER = "api.pluggie.net"
POLL_STAMP_FILE = "/tmp/pluggie_mtls_poll"
PULL_REQUEST_FILE = "/tmp/pluggie_commands_pull"
LEGACY_POLL_FILE = "/tmp/pluggie_commands_legacy"
PULL_DOORBELL = "doorbell"
LOCK_FILE = "/tmp/pluggie_commands.lock"
CONFIG_REFRESH_TRIGGER = "/tmp/pluggie_config_refresh"
POLL_INTERVAL = 60
DOORBELL_INTERVAL = 5
RETRY_MAX_INTERVAL = 900
TYPE_MTLS_DISABLE = "mtls_disable"
TYPE_CONFIG_REFRESH = "config_refresh"
EVENT_STATE_MISSING = "state_missing"
EVENTS_FILE = "remote_events.json"
REPORTED_MODE_FILE = "reported_mode.json"
MAX_EVENTS = 20
ACK_RETRY_WINDOW = datetime.timedelta(days=7)
REQUEST_TIMEOUT = 10
PROOF_TIMEOUT = 15
DETAIL_MAX = 200

_COMMAND_ID_RE = re.compile(
    r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")
_APISERVER_RE = re.compile(r"\A[A-Za-z0-9.-]{1,253}(?::[0-9]{1,5})?\Z")
_RECOVERY_URL_RE = re.compile(r"\Ahttps://[^\s\"'<>\\`]{1,2040}\Z")
_HOSTNAME_RE = re.compile(r"\A[A-Za-z0-9.-]{1,253}\Z")


class RemoteError(Exception):
    def __init__(self, status, message):
        super().__init__(message)
        self.status = status
        self.message = message


def _api_context():
    """Return (base_url, headers), or None without a usable access key."""
    try:
        with open(OPTIONS_FILE, "r") as f:
            options = json.load(f)
    except (OSError, ValueError) as exc:
        logging.debug(
            f"mTLS remote: cannot read options: {type(exc).__name__}")
        return None
    if not isinstance(options, dict):
        return None
    configuration = options.get("configuration")
    access_key = (configuration.get("access_key")
                  if isinstance(configuration, dict) else None)
    if not isinstance(access_key, str) or access_key in ("", "XXXXX"):
        return None
    pluggie_config = options.get("pluggie_config")
    api_server = (pluggie_config.get("apiserver")
                  if isinstance(pluggie_config, dict) else None)
    api_server = api_server or DEFAULT_APISERVER
    if not isinstance(api_server, str) or not _APISERVER_RE.match(api_server):
        logging.warning("mTLS remote: invalid apiserver in options")
        return None
    user_agent = options.get("user_agent")
    if not isinstance(user_agent, str) or not user_agent.isprintable():
        user_agent = "Pluggie-Client"
    headers = {
        "Authorization": f"Bearer {access_key}",
        "User-Agent": user_agent,
        "Accept": "application/json",
    }
    return f"https://{api_server}", headers


def load_events():
    data = mtls._read_json(EVENTS_FILE, {})
    events = data.get("events") if isinstance(data, dict) else None
    if not isinstance(events, list):
        return []
    return [e for e in events if isinstance(e, dict)]


def _save_events(events):
    mtls._write_json(EVENTS_FILE, {"events": events[-MAX_EVENTS:]})


def _update_events(change):
    with mtls.locked():
        events = load_events()
        change(events)
        _save_events(events)


def remote_notice():
    """Latest remote disable not yet dismissed in the UI, or None."""
    for event in reversed(load_events()):
        if (event.get("type") == "mtls_disable"
                and event.get("result") == "done"):
            if event.get("dismissed"):
                return None
            return {"time": event.get("time"), "id": event.get("id")}
    return None


def dismiss_notice():
    def change(events):
        for event in events:
            if event.get("type") == TYPE_MTLS_DISABLE:
                event["dismissed"] = True

    _update_events(change)


def note_state_missing():
    """The apiserver last saw mode test/on, but this app reports off
    because its client certificate data is missing."""
    def change(events):
        if any(e.get("type") == EVENT_STATE_MISSING
               and not e.get("dismissed") for e in events):
            return
        events.append({
            "type": EVENT_STATE_MISSING,
            "time": mtls._iso(mtls._now()),
            "acked": True,
            "dismissed": False,
        })

    _update_events(change)
    logging.warning("mTLS: client certificate data is missing, client "
                    "certificates are off. Restore a backup or set up "
                    "client certificates again.")


def state_notice():
    """Missing client certificate data not yet set up again, or None."""
    if mtls.load_ca_cert() is not None:
        return None
    if mtls.state_missing_locally():
        return {"time": None}
    for event in reversed(load_events()):
        if event.get("type") == EVENT_STATE_MISSING:
            if event.get("dismissed"):
                return None
            return {"time": event.get("time")}
    return None


def dismiss_state_notice():
    mtls.acknowledge_missing_state()

    def change(events):
        for event in events:
            if event.get("type") == EVENT_STATE_MISSING:
                event["dismissed"] = True

    _update_events(change)


def reported_mode():
    """Mode last reported to the apiserver ("off" when never reported)."""
    data = mtls._read_json(REPORTED_MODE_FILE, {})
    mode = data.get("mode") if isinstance(data, dict) else None
    return mode if mode in mtls.MODES else "off"


def _save_reported_mode(mode):
    if reported_mode() == mode:
        return
    mtls._ensure_dir()
    mtls._write_json(REPORTED_MODE_FILE,
                     {"mode": mode, "time": mtls._iso(mtls._now())})


def _throttled(now, interval=POLL_INTERVAL):
    try:
        last = os.path.getmtime(POLL_STAMP_FILE)
    except OSError:
        return False
    return 0 <= now - last < interval


def _touch_stamp(now):
    with open(POLL_STAMP_FILE, "a"):
        pass
    os.utime(POLL_STAMP_FILE, (now, now))


def request_pull(doorbell=False):
    """Ask for one command fetch (start, reconnect, missed doorbell)."""
    try:
        if doorbell or not os.path.exists(PULL_REQUEST_FILE):
            with open(PULL_REQUEST_FILE, "w") as f:
                f.write(PULL_DOORBELL if doorbell else "0")
    except OSError as exc:
        logging.debug(f"Cannot request a command fetch: {type(exc).__name__}")


def doorbell_pending():
    """True while a doorbell waits for the 5 s gap after the last fetch."""
    try:
        with open(PULL_REQUEST_FILE) as f:
            return f.read().strip() == PULL_DOORBELL
    except OSError:
        return False


def _pull_failures():
    try:
        with open(PULL_REQUEST_FILE) as f:
            return max(0, min(int(f.read().strip() or 0), 10))
    except (OSError, ValueError):
        return 0


def _record_pull_failure():
    failures = _pull_failures() + 1
    try:
        with open(PULL_REQUEST_FILE, "w") as f:
            f.write(str(failures))
    except OSError:
        pass


def _clear_pull_request():
    try:
        os.remove(PULL_REQUEST_FILE)
    except OSError:
        pass


def _set_legacy_poll(enabled):
    """Apiservers without doorbell are polled every 60 s while mTLS is on."""
    try:
        if enabled:
            with open(LEGACY_POLL_FILE, "a"):
                pass
        else:
            os.remove(LEGACY_POLL_FILE)
    except OSError:
        pass


@contextlib.contextmanager
def _locked():
    with open(LOCK_FILE, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _ack_pending(event, now_dt):
    if event.get("acked"):
        return False
    try:
        created = datetime.datetime.fromisoformat(
            str(event.get("time")).replace("Z", "+00:00"))
    except ValueError:
        return False
    return now_dt - created < ACK_RETRY_WINDOW


def _report_params(mode):
    params = {"mode": mode}
    if mode == "off":
        reason = mtls.off_reason()
        if reason:
            params["reason"] = reason
    return params


def fetch_commands(session, context, mode):
    """Return (commands, hostname, doorbell) from the apiserver."""
    base_url, headers = context
    try:
        response = session.get(
            f"{base_url}/api/addon/commands", headers=headers,
            params=_report_params(mode), timeout=REQUEST_TIMEOUT,
            allow_redirects=False)
    except requests.RequestException as exc:
        raise RemoteError(None, f"connection failed ({type(exc).__name__})")
    if response.status_code != 200:
        raise RemoteError(response.status_code, f"HTTP {response.status_code}")
    try:
        data = response.json()
    except ValueError:
        data = None
    commands = data.get("commands") if isinstance(data, dict) else None
    if not isinstance(commands, list):
        raise RemoteError(200, "invalid response")
    if mode == "off" and data.get("mtls_state_missing") is True:
        note_state_missing()
    return commands, data.get("hostname"), data.get("doorbell") is True


def _local_hostname():
    try:
        with open(OPTIONS_FILE, "r") as f:
            options = json.load(f)
        return options.get("pluggie_config", {}).get("hostname")
    except (OSError, ValueError, AttributeError):
        return None


def note_hostname(hostname):
    """Request a config refresh when the apiserver reports another
    hostname (the apiserver adds it to the commands response)."""
    if not isinstance(hostname, str) or not _HOSTNAME_RE.match(hostname):
        return False
    local = _local_hostname()
    if not isinstance(local, str) or not local:
        return False
    if hostname.rstrip(".").lower() == local.strip().rstrip(".").lower():
        return False
    if os.path.exists(CONFIG_REFRESH_TRIGGER):
        return True
    logging.warning(f"Tunnel hostname changed to {hostname} in the Pluggie "
                    f"account, refreshing configuration")
    try:
        with open(CONFIG_REFRESH_TRIGGER, "a"):
            pass
    except OSError as exc:
        logging.debug(f"Cannot request config refresh: {type(exc).__name__}")
        return False
    return True


def send_ack(session, context, event):
    """Ack one executed command; return True once the apiserver has it."""
    base_url, headers = context
    command_id = event["id"]
    payload = {
        "result": event.get("result"),
        "detail": str(event.get("detail", ""))[:DETAIL_MAX],
    }
    try:
        response = session.post(
            f"{base_url}/api/addon/commands/{command_id}/ack",
            headers=headers, json=payload, timeout=REQUEST_TIMEOUT)
        status = response.status_code
    except requests.RequestException as exc:
        logging.warning(
            f"mTLS remote: ack of command {command_id} failed "
            f"({type(exc).__name__}), retrying later")
        return False
    if status not in (200, 404):
        logging.warning(
            f"mTLS remote: ack of command {command_id} failed "
            f"(HTTP {status}), retrying later")
        return False
    if status == 404:
        logging.debug(
            f"mTLS remote: command {command_id} unknown to apiserver")

    def change(events):
        for item in events:
            if item.get("id") == command_id:
                item["acked"] = True

    _update_events(change)
    return True


def execute(command):
    """Run one command; return (result, detail)."""
    if command.get("type") == TYPE_CONFIG_REFRESH:
        try:
            with open(CONFIG_REFRESH_TRIGGER, "a"):
                pass
        except OSError as exc:
            logging.error(f"Cannot request a configuration refresh: "
                          f"{type(exc).__name__}")
            return "failed", "cannot request a configuration refresh"
        logging.warning("Tunnel settings changed in the Pluggie account, "
                        "refreshing configuration")
        return "done", "refresh requested"
    if command.get("type") != TYPE_MTLS_DISABLE:
        return "failed", "unsupported command type"
    try:
        if mtls.effective_mode(mtls.load_state()) == "off":
            return "done", "already off"
        mtls.set_mode("off", reason="remote")
    except mtls.MtlsError as exc:
        logging.error(f"mTLS remote: turning off failed: {exc.message}")
        return "failed", exc.message[:DETAIL_MAX]
    except Exception as exc:
        logging.error(f"mTLS remote: turning off failed: {type(exc).__name__}")
        return "failed", "internal error"
    return "done", "mode off"


def poll(now=None, force=False):
    """Fetch and run pending commands when due; return the number of
    executed commands. force: doorbell, fetch at once (5 s throttle)."""
    now = time.time() if now is None else now
    with _locked():
        return _poll(now, force)


def _poll(now, force):
    now_dt = datetime.datetime.fromtimestamp(now, datetime.timezone.utc)
    pending = [e for e in load_events() if _ack_pending(e, now_dt)]
    mode = mtls.effective_mode(mtls.load_state())
    requested = force or os.path.exists(PULL_REQUEST_FILE)
    report = reported_mode() != mode
    legacy = mode != "off" and os.path.exists(LEGACY_POLL_FILE)
    fetch = requested or report or legacy
    if not fetch and not pending:
        return 0

    interval = POLL_INTERVAL
    if force or (requested and doorbell_pending()):
        interval = DOORBELL_INTERVAL
    elif requested and not report and not legacy:
        interval = min(POLL_INTERVAL * 2 ** _pull_failures(),
                       RETRY_MAX_INTERVAL)
    if _throttled(now, interval):
        if force:
            request_pull(doorbell=True)
        return 0
    _touch_stamp(now)
    context = _api_context()
    if context is None:
        logging.debug("mTLS remote: no access key configured")
        _clear_pull_request()
        return 0

    with requests.Session() as session:
        for event in pending:
            send_ack(session, context, event)
        if not fetch:
            return 0
        try:
            commands, hostname, doorbell = fetch_commands(
                session, context, mode)
        except RemoteError as exc:
            logging.debug(
                f"mTLS remote: polling commands failed: {exc.message}")
            if exc.status is None or exc.status >= 500 or exc.status == 429:
                if requested:
                    _record_pull_failure()
                return 0
            # No commands endpoint (older apiserver) or key rejected:
            # nothing to retry until the next start, reconnect or change
            _save_reported_mode(mode)
            _clear_pull_request()
            _set_legacy_poll(False)
            return 0
        _save_reported_mode(mode)
        _clear_pull_request()
        _set_legacy_poll(not doorbell)
        note_hostname(hostname)
        executed = _run_commands(session, context, commands)
        if executed:
            _report_changed_mode(session, context, mode)
        return executed


def _report_changed_mode(session, context, old_mode):
    """Report a mode changed by a command at once, not after the throttle."""
    mode = mtls.effective_mode(mtls.load_state())
    if mode == old_mode:
        return
    try:
        fetch_commands(session, context, mode)
    except RemoteError as exc:
        logging.debug(f"mTLS remote: reporting the mode failed: {exc.message}")
        return
    _save_reported_mode(mode)


def _run_commands(session, context, commands):
    executed = 0
    for command in commands:
        if not isinstance(command, dict):
            continue
        command_id = command.get("id")
        if (not isinstance(command_id, str)
                or not _COMMAND_ID_RE.match(command_id)):
            logging.warning(
                "mTLS remote: ignoring a command with an invalid id")
            continue
        known = next(
            (e for e in load_events() if e.get("id") == command_id), None)
        if known is not None:
            send_ack(session, context, known)
            continue

        result, detail = execute(command)
        executed += 1
        if result == "done" and command.get("type") == TYPE_MTLS_DISABLE:
            logging.warning(
                "mTLS: client certificate authentication was turned off "
                f"remotely from the Pluggie account (command {command_id})")
        event = {
            "id": command_id,
            "type": str(command.get("type"))[:64],
            "time": mtls._iso(mtls._now()),
            "result": result,
            "detail": detail,
            "acked": False,
            "dismissed": False,
        }
        _update_events(lambda events: events.append(event))
        send_ack(session, context, event)
    return executed


def ownership_proof(code):
    """Exchange a support code for a one-time account recovery URL."""
    context = _api_context()
    if context is None:
        raise RemoteError(409, "The access key is not configured")
    base_url, headers = context
    try:
        response = requests.post(
            f"{base_url}/api/addon/ownership-proof", headers=headers,
            json={"code": code}, timeout=PROOF_TIMEOUT)
    except requests.RequestException as exc:
        logging.warning(
            f"Account recovery: cannot reach the Pluggie server "
            f"({type(exc).__name__})")
        raise RemoteError(
            502, "Cannot reach the Pluggie server. Check the internet "
                 "connection and try again.")

    status = response.status_code
    if status == 200:
        try:
            data = response.json()
        except ValueError:
            data = None
        url = data.get("recovery_url") if isinstance(data, dict) else None
        expires = data.get("expires") if isinstance(data, dict) else None
        if (not isinstance(url, str) or not _RECOVERY_URL_RE.match(url)
                or not isinstance(expires, str) or len(expires) > 64):
            logging.warning("Account recovery: unexpected response from the "
                            "Pluggie server")
            raise RemoteError(
                502, "Unexpected response from the Pluggie server")
        logging.debug("USER_ACTIVITY: ownership_proof result=verified")
        return {"recovery_url": url, "expires": expires}

    logging.debug(
        f"USER_ACTIVITY: ownership_proof result=rejected status={status}")
    if status == 400:
        raise RemoteError(
            400, "The code is invalid or has expired. Ask Pluggie support "
                 "for a new code.")
    if status == 429:
        raise RemoteError(
            429, "Too many attempts. Wait 15 minutes and try again.")
    if status in (401, 403):
        raise RemoteError(
            502, "The Pluggie server rejected this app's access key or the "
                 "tunnel is disabled.")
    raise RemoteError(
        502, f"Unexpected response from the Pluggie server (HTTP {status})")


def main(argv):
    if argv != ["poll"]:
        sys.stderr.write("usage: mtls_remote.py poll\n")
        return 2
    setup_logging()
    try:
        poll()
    except Exception as exc:
        logging.error(f"mTLS remote: poll failed: {type(exc).__name__}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
