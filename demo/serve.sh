#!/bin/sh
# Serve the simulated lure on loopback only. Open http://127.0.0.1:8765/lure.html
cd "$(dirname "$0")" && exec python3 -m http.server 8765 --bind 127.0.0.1
