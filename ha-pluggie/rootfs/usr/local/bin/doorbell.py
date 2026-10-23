#!/usr/local/bin/python
"""Doorbell: the Pluggie endpoint sends one UDP datagram over WireGuard when
the apiserver has a command for this app; the app then fetches its pending
commands at once instead of polling the apiserver.

Accepted only on the WireGuard interface, from the endpoint's tunnel
address. The datagram carries no data; the fetch itself is authenticated
with the access key.
"""

import ipaddress
import json
import logging
import os
import re
import socket
import struct
import threading
import time

import mtls_remote

OPTIONS_FILE = "/data/pluggie.json"
WG_CONFIG_DIR = "/etc/wireguard"
DOORBELL_PORT = 54004
PAYLOAD_PREFIX = b"pluggie-doorbell"
RECV_TIMEOUT = 60
RETRY_DELAY = 10

_IP_FREEBIND = getattr(socket, "IP_FREEBIND", 15)
_IP_PKTINFO = getattr(socket, "IP_PKTINFO", 8)
_PKTINFO = struct.Struct("@i4s4s")
_INTERFACE_RE = re.compile(r"\A[A-Za-z0-9_.-]{1,15}\Z")


def tunnel_params():
    """(interface, tunnel IP, endpoint tunnel IP) or None before setup."""
    try:
        with open(OPTIONS_FILE, "r") as f:
            config = json.load(f).get("pluggie_config") or {}
        interface = config.get("interface1")
        edge_ip = str(ipaddress.IPv4Address(config.get("endpoint1_ip_int")))
        if not isinstance(interface, str) or not _INTERFACE_RE.match(interface):
            return None
        with open(os.path.join(WG_CONFIG_DIR, f"{interface}.conf"), "r") as f:
            for line in f:
                key, _, value = line.partition("=")
                if key.strip() == "Address":
                    address = value.strip().split(",")[0].split("/")[0]
                    local_ip = str(ipaddress.IPv4Address(address))
                    return interface, local_ip, edge_ip
    except (OSError, ValueError, AttributeError, TypeError):
        pass
    return None


def accepted(data, ancdata, address, interface, edge_ip):
    """True for a doorbell from the endpoint received on the tunnel."""
    if not address or address[0] != edge_ip:
        return False
    if not data.startswith(PAYLOAD_PREFIX):
        return False
    for level, kind, value in ancdata:
        if (level == socket.IPPROTO_IP and kind == _IP_PKTINFO
                and len(value) >= _PKTINFO.size):
            ifindex = _PKTINFO.unpack_from(value)[0]
            try:
                return ifindex == socket.if_nametoindex(interface)
            except OSError:
                return False
    return False


def open_socket(local_ip, port=DOORBELL_PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # The tunnel address may not exist yet when the app starts
        sock.setsockopt(socket.IPPROTO_IP, _IP_FREEBIND, 1)
        sock.setsockopt(socket.IPPROTO_IP, _IP_PKTINFO, 1)
        sock.bind((local_ip, port))
        sock.settimeout(RECV_TIMEOUT)
    except OSError:
        sock.close()
        raise
    return sock


def ring(wait=time.sleep):
    try:
        mtls_remote.poll(force=True)
        # Rung right after another fetch: fetch once the 5 s gap is over
        if mtls_remote.doorbell_pending():
            wait(mtls_remote.DOORBELL_INTERVAL)
            mtls_remote.poll(force=True)
    except Exception as exc:
        logging.error(f"Doorbell: fetching commands failed: "
                      f"{type(exc).__name__}")


def serve(stop=None, on_ring=ring, port=DOORBELL_PORT):
    stop = stop or threading.Event()
    warned = False
    while not stop.is_set():
        params = tunnel_params()
        if params is None:
            stop.wait(RETRY_DELAY)
            continue
        interface, local_ip, edge_ip = params
        try:
            sock = open_socket(local_ip, port)
        except OSError as exc:
            log = logging.debug if warned else logging.warning
            log(f"Doorbell: cannot listen on {local_ip}:{port} "
                f"({type(exc).__name__})")
            warned = True
            stop.wait(RETRY_DELAY)
            continue
        warned = False
        logging.debug(f"Doorbell listening on {local_ip}:{port}/udp")
        with sock:
            while not stop.is_set():
                try:
                    data, ancdata, _flags, address = sock.recvmsg(
                        256, socket.CMSG_SPACE(_PKTINFO.size))
                except socket.timeout:
                    if tunnel_params() != params:
                        break
                    continue
                except OSError as exc:
                    logging.debug(f"Doorbell: receive failed "
                                  f"({type(exc).__name__})")
                    stop.wait(1)
                    break
                if not accepted(data, ancdata, address, interface, edge_ip):
                    logging.debug("Doorbell: ignored a datagram")
                    continue
                logging.debug("Doorbell rang, fetching commands")
                on_ring()
                if tunnel_params() != params:
                    break


def start_doorbell_thread():
    thread = threading.Thread(target=serve, daemon=True)
    thread.name = "doorbell"
    thread.start()
    return thread
