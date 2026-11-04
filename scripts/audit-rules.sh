#!/bin/sh
# Install the execve audit rule clickfixed's audit backend reads. Run as root.
set -eu
auditctl -a always,exit -F arch=b64 -S execve -k clickfixed
auditctl -a always,exit -F arch=b32 -S execve -k clickfixed
echo "execve audit rules installed (key: clickfixed). Persist via /etc/audit/rules.d/ if wanted."
