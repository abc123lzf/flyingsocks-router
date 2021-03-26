#!/usr/bin/env sh

fs_pid=$(cat /var/run/fscli.pid)
if [ -z "$fs_pid" ]; then
  echo "Program not start"
  exit 1
fi

rm -f /var/run/fscli.pid

echo "Kill process $fs_pid"
kill -15 "$fs_pid"

echo "Restore iptables ..."
if [ ! -f "iptables.bak" ]; then
  echo "WARN: iptables config backup file $0/iptables.bak not found, Could not restore iptables"
  exit 1
fi

iptables-restore < iptables.bak
echo "Done"