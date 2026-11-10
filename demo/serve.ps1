# Serve the simulated lure on loopback only. Open http://127.0.0.1:8765/lure.html
# Needs Python 3 (python.org or the Microsoft Store).
Set-Location $PSScriptRoot
python -m http.server 8765 --bind 127.0.0.1
