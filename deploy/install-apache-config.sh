#!/bin/bash
set -Eeuo pipefail

APP_DIR=${VULNARCHIVE_APP_DIR:-/opt/vulnarchive}
SOURCE=${VULNARCHIVE_APACHE_SOURCE:-$APP_DIR/deploy/apache-vuln.freearchive.org.conf}
TARGET=${VULNARCHIVE_APACHE_SITE:-/etc/apache2/sites-available/vuln.freearchive.org.conf}

if [[ $EUID -ne 0 ]]; then
    echo "error: run this installer with sudo or as root" >&2
    exit 1
fi
for command in apachectl install readlink systemctl; do
    command -v "$command" >/dev/null || { echo "error: missing command: $command" >&2; exit 1; }
done
[[ -f $SOURCE ]] || { echo "error: missing Apache template: $SOURCE" >&2; exit 1; }

backup=""
if [[ -e $TARGET ]]; then
    backup="$TARGET.backup.$(date -u +%Y%m%dT%H%M%SZ)"
    cp -a -- "$TARGET" "$backup"
    echo "==> Existing virtual host backed up to $backup"
fi

restore() {
    result=$?
    if (( result != 0 )); then
        if [[ -n $backup ]]; then
            cp -a -- "$backup" "$TARGET"
        else
            rm -f -- "$TARGET"
        fi
        echo "error: Apache configuration was restored after a failed validation" >&2
    fi
}
trap restore EXIT

install -m 0644 "$SOURCE" "$TARGET"
enabled=0
for site in /etc/apache2/sites-enabled/*; do
    [[ -e $site ]] || continue
    if [[ $(readlink -f -- "$site") == $(readlink -f -- "$TARGET") ]]; then
        enabled=1
        break
    fi
done
if (( ! enabled )); then
    echo "error: $TARGET is not enabled; set VULNARCHIVE_APACHE_SITE to the active vhost shown by apachectl -S" >&2
    exit 1
fi
apachectl configtest
systemctl reload apache2
trap - EXIT
echo "==> Installed $TARGET and reloaded Apache"
echo "==> /vulnerability/ is now proxied to the VULNARCHIVE public service"
