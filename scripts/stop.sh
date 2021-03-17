#!/usr/bin/env sh

fs_pid=$(pidof fscli)
if [ -z "$fs_pid" ]; then
  echo "Program not start"
  exit 1
fi

echo "Kill process $fs_pid"
kill -15 "$fs_pid"

echo "Restore iptables ..."
if [ ! -f "$0/iptables.bak" ]; then
  echo "WARN: iptables config backup file $0/iptables.bak not found, Could not restore iptables"
  exit 1
fi

iptables-restore < iptables.bak
echo "Done"