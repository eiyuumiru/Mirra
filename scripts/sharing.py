#!/usr/bin/env python3
"""Temporarily load the Mirra keystore adapter into Apple's sharingd job, then restart it unmodified."""
import argparse
import base64
import json
import os
import plistlib
import signal
import socket
import struct
import threading
import time
from pathlib import Path
from configuration import load_config
from lifetime import add_lifetime_arguments,duration_from_arguments,deadline_for,watch_parent_pipe,emit_event
from logs import BoundedLogs
from sharingd import SharingdAgent,service,is_original,ORIGINAL_PLIST,backup_pairing

ROOT = Path(__file__).resolve().parents[1] / "runtime"
WORKSPACE = ROOT / "host"
DOMAIN = f"gui/{os.getuid()}"
ORIGINAL = f"{DOMAIN}/com.apple.sharingd"
parser = argparse.ArgumentParser(description=__doc__)
add_lifetime_arguments(parser)
parser.add_argument("--config")
parser.add_argument('--parent-lifeline',action='store_true',help=argparse.SUPPRESS)
args = parser.parse_args()
configuration = load_config(args.config)
WORKSPACE = configuration.runtime_directory
duration = duration_from_arguments(parser,args,configuration.seconds)
LABEL = "com.apple.sharingd"
TARGET = ORIGINAL


def readn(sock, count):
    data = b""
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise ConnectionError("broker disconnected")
        data += part
    return data


broker = json.loads((WORKSPACE / "broker-state.json").read_text())
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.settimeout(15)
    connection.connect(broker["socket"])
    message = json.dumps({"operation": "health"}).encode()
    connection.sendall(struct.pack(">I", len(message)) + message)
    size = struct.unpack(">I", readn(connection, 4))[0]
    if not 0 < size <= 262144:
        raise SystemExit("Invalid broker health response length")
    health = json.loads(readn(connection, size))
if not health.get("ready"):
    raise SystemExit("Live USB/SEP broker health check failed")
if 'reset_owned_sessions' not in health.get('capabilities', []):
    raise SystemExit('Broker/shim protocol mismatch: rebuild and restart support together')
original_before = service(ORIGINAL)
if not is_original(original_before):
    raise SystemExit(f"Unexpected original service state: {original_before}")
if original_before.get("injected"):
    raise SystemExit("sharingd already has an injected configuration; restore that session before starting another")
if TARGET != ORIGINAL and service(TARGET):
    raise SystemExit("A Mirra sharingd job is already registered")
WORKSPACE.chmod(0o700)
# Read by the adapter inside sharingd only; never placed in launchd's environment.
# Survives Mirra stops: Apple's sharingd deletes the pairing key when it runs alone.
STATE = Path.home() / "Library/Application Support/Mirra/state"
STATE.mkdir(mode=0o700, parents=True, exist_ok=True)
if STATE.stat().st_uid != os.getuid() or STATE.stat().st_mode & 0o077:
    raise SystemExit("Mirra state directory must be private")
PAIRING_BACKUP = STATE / "pairing.plist"
BROKER_FILE = STATE / "broker.json"
# A detached sharingd outlives this workspace, so its output goes to a stable file.
LOGS = Path.home() / "Library/Application Support/Mirra/logs"
LOGS.mkdir(mode=0o700, parents=True, exist_ok=True)
if LOGS.stat().st_uid != os.getuid() or LOGS.stat().st_mode & 0o077:
    raise SystemExit("Mirra log directory must be private")
SHARINGD_LOGS = {1: LOGS / "sharingd.stdout.log", 2: LOGS / "sharingd.log"}


def publish_broker(online):
    """Rewrite the broker file in place: the adapter reads it through a descriptor
    opened before sharingd's sandbox started, so the inode must not change."""
    value = {"online": online}
    if online:
        value.update(socket=broker["socket"], tcp_port=broker["tcp_port"], token=broker["auth_token"],
                     certificate=base64.b64encode(Path(broker["certificate"]).read_bytes()).decode())
    data = json.dumps(value).encode()
    descriptor = os.open(BROKER_FILE, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise RuntimeError("Mirra broker file must be private")
        os.ftruncate(descriptor, 0)
        os.pwrite(descriptor, data, 0)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


settings = {
    "attested_ltk_backup": str(STATE / "attested-ltk.plist"),
    "broker_file": str(BROKER_FILE),
    "stdout": str(SHARINGD_LOGS[1]),
    "stderr": str(SHARINGD_LOGS[2]),
    "environment": {
        "MIRRA_KEYSTORE_BROKER_SOCKET": broker["socket"],
        "MIRRA_KEYSTORE_BROKER_TCP_PORT": str(broker["tcp_port"]),
        "MIRRA_KEYSTORE_BROKER_TOKEN": broker["auth_token"],
        "MIRRA_KEYSTORE_DCRT_PATH": broker["certificate"],
        "MIRRA_KEYSTORE_DIAGNOSTIC_ERRORS": "1",
        "MIRRA_ASSERT_DELAY_MODE": "2",
        "MIRRA_PAIRING_TRANSPORT": "wifi",
    },
}
for path in SHARINGD_LOGS.values():
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    os.close(descriptor)
publish_broker(True)
stop = threading.Event()
signal.signal(signal.SIGTERM, lambda *_: stop.set())
signal.signal(signal.SIGINT, lambda *_: stop.set())
if args.parent_lifeline:
    watch_parent_pipe(0,stop.set)
log_limits=BoundedLogs(on_error=stop.set)
agent = SharingdAgent(WORKSPACE)
failed = False
try:
    if stop.is_set():
        raise InterruptedError('Parent ended before sharingd startup')
    agent.start(WORKSPACE / "keystore.dylib", settings, PAIRING_BACKUP,
                reuse_detached=health.get('can_resume_pairing') is True)
    if agent.adopted:
        # The adapter from an earlier session is still loaded; it reads the new
        # broker from BROKER_FILE, and sharingd keeps the iPhone pairing armed.
        state = service(TARGET)
        if str(state.get("pid")) != str(agent.record.get("injected_pid")):
            raise RuntimeError("The detached sharingd adapter is no longer running")
    else:
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if stop.is_set():
                raise InterruptedError('Parent ended during sharingd startup')
            state = service(TARGET)
            if state.get("state") == "running" and state.get("pid"):
                marker = f"MIRRA_KEYSTORE_SHIM_LOADED pid={state['pid']} enabled=1"
                if marker in SHARINGD_LOGS[2].read_text(errors="replace"):
                    break
            time.sleep(0.2)
        else:
            raise RuntimeError(f"sharingd did not load the adapter: {state}")
        agent.record_injected(state['pid'])
    for fd, path in SHARINGD_LOGS.items():
        log_limits.watch_native(path, int(state['pid']), fd)
    record = {"controller_pid": os.getpid(), "job": TARGET, "state": state,
              "restored_pairing_entries": agent.restored_pairing, "adopted_sharingd": agent.adopted,
              "original_before": original_before, "automatic_restore_seconds": duration}
    (WORKSPACE / "sharing.json").write_text(json.dumps(record, indent=2) + "\n")
    emit_event({"WORKSPACE_RUNNING": record})
    deadline = deadline_for(duration)
    ticks = 0
    while not stop.wait(1) and time.monotonic() < deadline:
        ticks += 1
        if ticks % 10 == 0:
            try:
                backup_pairing(PAIRING_BACKUP)
            except (OSError, ValueError) as error:
                emit_event({"PAIRING_BACKUP_FAILED": str(error)})
        # Apple's job restarts sharingd by itself, but never with the adapter.
        if service(TARGET).get("pid") != state["pid"]:
            raise RuntimeError("sharingd restarted without the Mirra adapter")
except BaseException:
    failed = True
    raise
finally:
    try:
        if agent.owned:
            try:
                # Before Apple's sharingd runs again and removes the entries.
                backup_pairing(PAIRING_BACKUP)
            except (OSError, ValueError) as error:
                emit_event({"PAIRING_BACKUP_FAILED": str(error)})
            try:
                publish_broker(False)  # The adapter keeps the pairing while offline.
            except (OSError, RuntimeError) as error:
                emit_event({"BROKER_FILE_FAILED": str(error)})
            # Only a normal stop of the long-running service keeps the adapter.
            detach = stop.is_set() and duration is None and not failed and log_limits.error is None
            state = agent.close(detach=detach)
            emit_event({"SHARINGD_DETACHED" if detach else "ORIGINAL_RESTORED": state})
    finally:
        (WORKSPACE/'sharingd-log-limits.json').write_text(json.dumps(log_limits.close(),indent=2)+'\n')

if log_limits.error:
    raise SystemExit('Diagnostic log maintenance failed; original sharingd restoration was attempted')
