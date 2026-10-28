#!/bin/sh
# Shared dependency bootstrap: preserve service policy; never start/restart daemons.
set -eu
test "$(id -u)" -eq 0
test -r /etc/os-release
# shellcheck disable=SC1091
. /etc/os-release
case "$ID" in ubuntu|debian) ;; *) echo 'Only Ubuntu/Debian supported' >&2; exit 1;; esac
test -d /run/systemd/system || { echo 'systemd is required' >&2; exit 1; }
for pkg in "$@"; do
    case "$pkg" in python3|openssh-client|nftables|iproute2|util-linux|procps|passwd) ;; *) exit 2;; esac
done
test "$#" -gt 0 || exit 0
command -v flock >/dev/null || { echo 'flock (util-linux) is required for safe dependency bootstrap' >&2; exit 1; }
exec 9>/run/tblockerbridge-packages.lock
flock -n 9 || { echo 'Another dependency bootstrap is running' >&2; exit 1; }
policy=/usr/sbin/policy-rc.d
backup=$(mktemp -d /run/tblockerbridge-policy.XXXXXX)
had_policy=0
nft_requested=0
for pkg in "$@"; do if [ "$pkg" = nftables ]; then nft_requested=1; fi; done
nft_before=$(systemctl is-enabled nftables.service 2>/dev/null || true)
if [ -e "$policy" ] || [ -L "$policy" ]; then mv -- "$policy" "$backup/original"; had_policy=1; fi
restore() {
    rm -f -- "$policy"
    if [ "$had_policy" -eq 1 ]; then mv -- "$backup/original" "$policy"; fi
    rmdir -- "$backup"
    # A postinst may enable a newly installed nftables.service even when its
    # immediate start is denied. Prevent it flushing somebody's rules on reboot.
    if [ "$nft_requested" -eq 1 ]; then
        case "$nft_before" in
            ''|not-found|disabled) systemctl disable nftables.service >/dev/null 2>&1 || true ;;
        esac
    fi
}
trap restore EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
printf '#!/bin/sh\nexit 101\n' > "$policy"
chmod 755 "$policy"
# needrestart must not choose daemon restarts on distributions that install it.
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l
apt-get update
apt-get -y --no-install-recommends -o Dpkg::Options::=--force-confold install "$@"
