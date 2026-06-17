#!/usr/bin/env python3
"""
Test multiple tunnel sessions with ping or streaming modes.

Usage:
    python3 test_tunnel.py [OPTIONS]

Options:
    -n, --num NUM    Number of ports/sessions (default: 3)
    -c, --conns NUM  Connections per port (default: 1)
    --port PORT      Base port (default: 17001)
    --stream SECS    Stream for SECS seconds (default: ping mode)
    --loop           Repeat continuously

Examples:
    python3 test_tunnel.py                 # Ping 3 ports (17001-17003)
    python3 test_tunnel.py -n 5            # Ping 5 ports
    python3 test_tunnel.py -c 3            # 3 connections per port (9 total)
    python3 test_tunnel.py --stream 10     # Stream for 10s
    python3 test_tunnel.py -n 2 -c 5 --stream 10  # 2 ports, 5 conns each
"""

import socket
import sys
import time
import threading
import hashlib
import random
import string
from dataclasses import dataclass, field

def parse_args():
    args = sys.argv[1:]
    if args and args[0] in ['-h', '--help']:
        print(__doc__)
        sys.exit(0)

    # Parse flags
    loop = '--loop' in args

    num_sessions = 3
    for flag in ['-n', '--num']:
        if flag in args:
            idx = args.index(flag)
            if idx + 1 < len(args):
                num_sessions = int(args[idx + 1])
            break

    conns_per_port = 1
    for flag in ['-c', '--conns']:
        if flag in args:
            idx = args.index(flag)
            if idx + 1 < len(args):
                conns_per_port = int(args[idx + 1])
            break

    base_port = 17001
    if '--port' in args:
        idx = args.index('--port')
        if idx + 1 < len(args):
            base_port = int(args[idx + 1])

    stream_duration = None
    if '--stream' in args:
        idx = args.index('--stream')
        if idx + 1 < len(args) and not args[idx + 1].startswith('-'):
            stream_duration = int(args[idx + 1])
        else:
            stream_duration = 5  # default

    return base_port, num_sessions, conns_per_port, stream_duration, loop

BASE_PORT, NUM_SESSIONS, CONNS_PER_PORT, STREAM_DURATION, LOOP_MODE = parse_args()

@dataclass
class Stats:
    port: int
    conn_id: int = 0
    sent_msgs: int = 0
    recv_msgs: int = 0
    sent_bytes: int = 0
    recv_bytes: int = 0
    errors: int = 0
    verified: int = 0
    corrupted: int = 0
    connected: bool = False
    sent_checksum: str = ""
    recv_checksum: str = ""
    _sent_hasher: object = field(default=None, repr=False)
    _recv_hasher: object = field(default=None, repr=False)

    def __post_init__(self):
        self._sent_hasher = hashlib.md5()
        self._recv_hasher = hashlib.md5()

    def update_sent(self, data: bytes):
        self._sent_hasher.update(data)
        self.sent_checksum = self._sent_hasher.hexdigest()[:16]

    def update_recv(self, data: bytes):
        self._recv_hasher.update(data)
        self.recv_checksum = self._recv_hasher.hexdigest()[:16]

    @property
    def label(self):
        if CONNS_PER_PORT > 1:
            return f"{self.port}#{self.conn_id}"
        return str(self.port)

def format_bytes(n: int) -> str:
    if n < 1024:
        return f"{n}B"
    elif n < 1024 * 1024:
        return f"{n/1024:.1f}KB"
    else:
        return f"{n/(1024*1024):.2f}MB"

first_connect_lock = threading.Lock()
first_connect_done = False

def stream_session(duration: float, stats: Stats):
    """Stream data through a tunnel for the specified duration."""
    global first_connect_done
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('127.0.0.1', stats.port))
        sock.setblocking(False)
        stats.connected = True
        with first_connect_lock:
            if not first_connect_done:
                print(f"\n[{stats.label}] Connected")
                first_connect_done = True
            else:
                print(f"[{stats.label}] Connected")

        end_time = time.time() + duration
        msg_num = 0
        recv_buf = b""
        pending_payloads = {}

        # Send phase
        send_end_time = end_time - 1.0  # Stop sending 1s early for drain
        while time.time() < send_end_time:
            try:
                rand_data = ''.join(random.choices(string.ascii_letters + string.digits, k=40))
                payload = f"SEQ{msg_num:06d}DATA{rand_data}"
                msg = f"{payload}\n"
                msg_bytes = msg.encode()
                sock.sendall(msg_bytes)
                pending_payloads[msg_num] = payload
                stats.sent_msgs += 1
                stats.sent_bytes += len(msg_bytes)
                stats.update_sent(msg_bytes)
                msg_num += 1
            except BlockingIOError:
                pass
            except Exception:
                stats.errors += 1

            try:
                data = sock.recv(8192)
                if data:
                    stats.recv_bytes += len(data)
                    stats.update_recv(data)
                    recv_buf += data
                    while b'\n' in recv_buf:
                        line, recv_buf = recv_buf.split(b'\n', 1)
                        stats.recv_msgs += 1
                        line_str = line.decode('utf-8', errors='replace')
                        found = False
                        for seq, payload in list(pending_payloads.items()):
                            if payload in line_str:
                                stats.verified += 1
                                del pending_payloads[seq]
                                found = True
                                break
                        if not found and 'SEQ' in line_str:
                            stats.corrupted += 1
            except BlockingIOError:
                pass
            except Exception:
                stats.errors += 1

            time.sleep(0.01)

        # Drain phase - receive remaining data
        while time.time() < end_time:
            try:
                data = sock.recv(8192)
                if data:
                    stats.recv_bytes += len(data)
                    stats.update_recv(data)
                    recv_buf += data
                    while b'\n' in recv_buf:
                        line, recv_buf = recv_buf.split(b'\n', 1)
                        stats.recv_msgs += 1
                        line_str = line.decode('utf-8', errors='replace')
                        found = False
                        for seq, payload in list(pending_payloads.items()):
                            if payload in line_str:
                                stats.verified += 1
                                del pending_payloads[seq]
                                found = True
                                break
                        if not found and 'SEQ' in line_str:
                            stats.corrupted += 1
            except BlockingIOError:
                pass
            except Exception:
                stats.errors += 1
            time.sleep(0.01)

        sock.close()
    except Exception as e:
        stats.errors += 1
        print(f"[{stats.label}] Error: {e}")

def test_port(port, iteration):
    """Single ping test - verify payload roundtrip."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('127.0.0.1', port))

        rand_data = ''.join(random.choices(string.ascii_letters + string.digits, k=50))
        payload = f"PING{iteration:04d}PORT{port}TEST{rand_data}"
        sock.sendall(f"{payload}\n".encode())
        sent_bytes = len(payload) + 1

        response = sock.recv(4096).decode('utf-8', errors='replace').strip()
        sock.close()
        recv_bytes = len(response)

        if payload in response:
            return port, True, f"sent={sent_bytes}B recv={recv_bytes}B OK"
        else:
            preview = response[:60] if len(response) > 60 else response
            return port, False, f"recv={recv_bytes}B got: {repr(preview)}"
    except Exception as e:
        return port, False, str(e)

def run_ping_once():
    """Single ping test."""
    total_conns = NUM_SESSIONS * CONNS_PER_PORT
    if CONNS_PER_PORT > 1:
        print(f"Pinging {NUM_SESSIONS} ports ({BASE_PORT}-{BASE_PORT + NUM_SESSIONS - 1}), {CONNS_PER_PORT} conns each = {total_conns} total")
    else:
        print(f"Pinging {NUM_SESSIONS} sessions (ports {BASE_PORT}-{BASE_PORT + NUM_SESSIONS - 1})")
    print("-" * 60)
    failures = 0
    for i in range(NUM_SESSIONS):
        port = BASE_PORT + i
        for c in range(CONNS_PER_PORT):
            _, success, response = test_port(port, 0)
            label = f"{port}#{c+1}" if CONNS_PER_PORT > 1 else str(port)
            status = "OK" if success else "FAIL"
            print(f"[{status}] {label}: {response}")
            if not success:
                failures += 1
    print("-" * 60)
    if failures == 0:
        print(f"✓ All {total_conns} connections OK")
    else:
        print(f"✗ {failures}/{total_conns} connection(s) failed")
        sys.exit(1)

def run_ping_loop():
    """Continuous ping test every 5 seconds."""
    run_ping_once()
    total_conns = NUM_SESSIONS * CONNS_PER_PORT
    print("\nContinuous testing (Ctrl+C to stop)...")
    try:
        iteration = 0
        while True:
            iteration += 1
            time.sleep(5)
            failures = 0
            print(f"[Iteration {iteration}]")
            for i in range(NUM_SESSIONS):
                port = BASE_PORT + i
                for c in range(CONNS_PER_PORT):
                    _, success, resp = test_port(port, iteration)
                    label = f"{port}#{c+1}" if CONNS_PER_PORT > 1 else str(port)
                    status = "OK" if success else "FAIL"
                    print(f"  [{status}] {label}: {resp}")
                    if not success:
                        failures += 1
            if failures == 0:
                print(f"  ✓ All {total_conns} connections OK")
            else:
                print(f"  ✗ {failures} connection(s) failed")
    except KeyboardInterrupt:
        print("\nStopped.")

def run_stream_once():
    """Single streaming test."""
    global first_connect_done
    first_connect_done = False
    total_conns = NUM_SESSIONS * CONNS_PER_PORT
    print(f"=== Streaming Test ({STREAM_DURATION}s) ===")
    if CONNS_PER_PORT > 1:
        print(f"Ports: {NUM_SESSIONS} ({BASE_PORT}-{BASE_PORT + NUM_SESSIONS - 1}), {CONNS_PER_PORT} conns each = {total_conns} total")
    else:
        print(f"Sessions: {NUM_SESSIONS} (ports {BASE_PORT}-{BASE_PORT + NUM_SESSIONS - 1})")
    print("-" * 70)

    stats_list = []
    for i in range(NUM_SESSIONS):
        for c in range(CONNS_PER_PORT):
            stats_list.append(Stats(port=BASE_PORT + i, conn_id=c + 1))
    threads = []

    for stats in stats_list:
        t = threading.Thread(target=stream_session, args=(STREAM_DURATION, stats))
        t.start()
        threads.append(t)

    start = time.time()
    while any(t.is_alive() for t in threads):
        elapsed = time.time() - start
        total_sent = sum(s.sent_bytes for s in stats_list)
        total_recv = sum(s.recv_bytes for s in stats_list)
        total_verified = sum(s.verified for s in stats_list)
        print(f"\r[{elapsed:.1f}s] Sent: {format_bytes(total_sent)}, Recv: {format_bytes(total_recv)}, Verified: {total_verified}", end="", flush=True)
        time.sleep(0.5)

    for t in threads:
        t.join()

    print("\n" + "-" * 70)
    print("Results:")
    total_sent_bytes = 0
    total_recv_bytes = 0
    total_verified = 0
    total_corrupted = 0
    total_errors = 0

    failures = 0
    for s in stats_list:
        checksum_match = s.sent_checksum and s.recv_checksum and s.sent_checksum == s.recv_checksum
        is_ok = s.connected and s.errors == 0 and s.corrupted == 0 and checksum_match
        status = "OK" if is_ok else "FAIL"
        if not is_ok:
            failures += 1
        if not s.sent_checksum or not s.recv_checksum:
            checksum_str = "✗ no data"
        elif checksum_match:
            checksum_str = f"✓{s.sent_checksum}"
        else:
            checksum_str = f"✗ sent={s.sent_checksum} recv={s.recv_checksum}"
        print(f"  [{status}] {s.label}: {format_bytes(s.sent_bytes)}↑ {format_bytes(s.recv_bytes)}↓ verified={s.verified} {checksum_str}")
        total_sent_bytes += s.sent_bytes
        total_recv_bytes += s.recv_bytes
        total_verified += s.verified
        total_corrupted += s.corrupted
        total_errors += s.errors

    print("-" * 70)
    print(f"Total: {format_bytes(total_sent_bytes)} sent, {format_bytes(total_recv_bytes)} recv, {total_verified} verified")
    print(f"Throughput: {format_bytes(int(total_sent_bytes/STREAM_DURATION))}/s")

    if failures > 0:
        print(f"*** {failures} FAILED ***")
        return False
    else:
        print("*** ALL OK ***")
        return True

def run_stream_loop():
    """Continuous streaming test."""
    print(f"Streaming {STREAM_DURATION}s every round (Ctrl+C to stop)...\n")
    try:
        iteration = 0
        while True:
            iteration += 1
            print(f"\n{'='*70}")
            print(f"Round {iteration}")
            print(f"{'='*70}")
            success = run_stream_once()
            if not success:
                print("Continuing despite errors...")
            print(f"\nWaiting 3s before next round...")
            time.sleep(3)
    except KeyboardInterrupt:
        print("\nStopped.")

if __name__ == '__main__':
    if STREAM_DURATION:
        if LOOP_MODE:
            run_stream_loop()
        else:
            run_stream_once()
    else:
        if LOOP_MODE:
            run_ping_loop()
        else:
            run_ping_once()
