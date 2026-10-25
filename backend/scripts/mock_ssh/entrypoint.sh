#!/bin/sh
set -eu
: "${MOCK_SSH_PASSWORD:?MOCK_SSH_PASSWORD is required by the test harness}"
echo "fttwmock:${MOCK_SSH_PASSWORD}" | chpasswd
unset MOCK_SSH_PASSWORD
rm -f /etc/ssh/ssh_host_ed25519_key /etc/ssh/ssh_host_ed25519_key.pub
ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key
chmod 600 /etc/ssh/ssh_host_ed25519_key
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
