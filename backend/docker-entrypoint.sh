#!/bin/sh
set -e

# ─── Docker socket group fix ──────────────────────────────────────────────────
# The Docker socket is owned by a host group (usually "docker", GID varies).
# We detect the socket's GID at runtime and add appuser to the matching group
# so cscli / docker-py commands work without running the whole app as root.
if [ -S /var/run/docker.sock ]; then
    SOCKET_GID=$(stat -c '%g' /var/run/docker.sock 2>/dev/null || echo "")
    if [ -n "$SOCKET_GID" ] && [ "$SOCKET_GID" != "0" ]; then
        # Create a group for that GID if it doesn't already exist
        if ! getent group "$SOCKET_GID" > /dev/null 2>&1; then
            addgroup --gid "$SOCKET_GID" dockersocket 2>/dev/null || \
            groupadd --gid "$SOCKET_GID" dockersocket 2>/dev/null || true
        fi
        SOCKET_GROUP=$(getent group "$SOCKET_GID" | cut -d: -f1)
        # Add appuser to that group (idempotent)
        adduser appuser "$SOCKET_GROUP" > /dev/null 2>&1 || \
        usermod -aG "$SOCKET_GROUP" appuser > /dev/null 2>&1 || true
    fi
fi

# ─── Traefik custom-config directory write permissions ────────────────────────
# The /traefik-custom volume is bind-mounted from the host and may be owned by
# root. appuser needs write access to create CrowdSec override YAML files.
if [ -d /traefik-custom ]; then
    chown appuser /traefik-custom 2>/dev/null || \
    chmod o+w  /traefik-custom 2>/dev/null || true
fi

# ─── Drop privileges and exec ─────────────────────────────────────────────────
exec gosu appuser "$@"
