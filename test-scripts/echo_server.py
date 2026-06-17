#!/usr/bin/env python3
"""
Simple multi-connection TCP echo server for testing tunnels.

This is the source service that the sender forwards traffic to.
In receiver-initiated mode, traffic flows:
  Test Client -> Receiver -> Sender -> Echo Server

Usage:
    python3 echo_server.py [PORT]

Each connection gets a unique ID and echoes back data.
"""

import socket
import threading
import sys
from datetime import datetime

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 19999
connection_count = 0
lock = threading.Lock()

def handle_client(conn, addr, conn_id):
    """Handle a single client connection."""
    print(f"[{conn_id}] Connected from {addr}")
    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            conn.sendall(data)
            msg = data.decode('utf-8', errors='replace').strip()
            print(f"[{conn_id}] Echoed: {msg[:50]}{'...' if len(msg) > 50 else ''}")
    except Exception as e:
        print(f"[{conn_id}] Error: {e}")
    finally:
        print(f"[{conn_id}] Disconnected")
        conn.close()

def main():
    global connection_count
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', PORT))
    server.listen(100)

    print(f"Echo server listening on port {PORT}")
    print("Press Ctrl+C to stop")
    print("-" * 40)

    try:
        while True:
            conn, addr = server.accept()
            with lock:
                connection_count += 1
                conn_id = f"C{connection_count:03d}"

            thread = threading.Thread(target=handle_client, args=(conn, addr, conn_id))
            thread.daemon = True
            thread.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        server.close()

if __name__ == '__main__':
    main()
