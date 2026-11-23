# lhm integration-test image: a real systemd-managed Ubuntu with every package
# lhm touches pre-installed, so scenarios test lhm's behaviour and not apt's.
#
# systemd as PID 1 in a container needs: --privileged, --cgroupns=private,
# and tmpfs mounts on /run and /run/lock (see run.sh). STOPSIGNAL SIGRTMIN+3
# makes `docker stop` shut systemd down cleanly.
FROM ubuntu:24.04

ENV container=docker \
    DEBIAN_FRONTEND=noninteractive \
    UV_PYTHON_INSTALL_DIR=/opt/uv-python \
    UV_PROJECT_ENVIRONMENT=/opt/lhm-venv \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=0

# uv binary from the official image (no host file copied into the build context).
COPY --from=ghcr.io/astral-sh/uv:0.13.7 /uv /usr/local/bin/uv

# Ubuntu 24.04 ships Python 3.12; lhm needs >= 3.15, which `uv sync --python 3.15`
# downloads as a managed CPython into /opt/uv-python at build time.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        systemd systemd-sysv dbus \
        openssh-server openssh-client \
        ufw iptables nftables \
        fail2ban python3-systemd \
        auditd \
        unattended-upgrades \
        logrotate ca-certificates curl iproute2 procps tar gzip kmod \
    && rm -rf /var/lib/apt/lists/*
# nftables is only a *Recommends* of fail2ban, so a --no-install-recommends
# install leaves `nft` missing and the template's `banaction =
# nftables-multiport` fails every ban at runtime (see scenarios/04).

# Package postinst scripts must not try to start units while systemd is not
# PID 1 yet; removed afterwards so runtime `apt-get install` behaves normally.
RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
 && chmod 0755 /usr/sbin/policy-rc.d

WORKDIR /opt/lhm
COPY pyproject.toml uv.lock ./
COPY src ./src
COPY templates ./templates
RUN uv sync --frozen --python 3.15 --no-dev \
 && ln -sf /opt/lhm-venv/bin/lhm /usr/local/bin/lhm \
 && lhm --help >/dev/null \
 && rm -f /usr/sbin/policy-rc.d

STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
