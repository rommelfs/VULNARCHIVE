#!/bin/bash
set -Eeuo pipefail
UPGRADE_SCRIPT_VERSION=2

# Complete in-place production upgrade for the deployment documented in
# DEPLOYMENT.md. Override paths through the environment for staging installs.
APP_DIR=${VULNARCHIVE_APP_DIR:-/opt/vulnarchive}
VENV_DIR=${VULNARCHIVE_VENV_DIR:-"$APP_DIR/.venv"}
ENV_FILE=${VULNARCHIVE_ENV_FILE:-/etc/vulnarchive/vulnarchive.env}
BACKUP_ROOT=${VULNARCHIVE_BACKUP_DIR:-/var/backups/vulnarchive}
DB_FILE=${VULNARCHIVE_DB_FILE:-"$APP_DIR/data/fd-sightings.sqlite"}
PYTHON=${PYTHON:-python3}
PULL=1

usage() {
    cat <<EOF
Usage: sudo $0 [--no-pull]
       $0 --version

Updates VULNARCHIVE, runs its tests, backs up SQLite and configuration, installs
the package and systemd units, migrates the store, restarts previously active
services, and checks the local public endpoint.

  --no-pull  install the currently checked-out revision without git pull
  --version  print the upgrade-script version and exit

Path overrides: VULNARCHIVE_APP_DIR, VULNARCHIVE_VENV_DIR,
VULNARCHIVE_ENV_FILE, VULNARCHIVE_BACKUP_DIR, VULNARCHIVE_DB_FILE, PYTHON.
EOF
}

case ${1:-} in
    "") ;;
    --no-pull) PULL=0 ;;
    --version) echo "VULNARCHIVE upgrade script $UPGRADE_SCRIPT_VERSION"; exit 0 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac

if [[ $EUID -ne 0 ]]; then
    echo "error: run this upgrade with sudo or as root" >&2
    exit 1
fi
echo "==> VULNARCHIVE upgrade script $UPGRADE_SCRIPT_VERSION"
for command in git systemctl install flock runuser curl; do
    command -v "$command" >/dev/null || { echo "error: missing command: $command" >&2; exit 1; }
done
[[ -d "$APP_DIR/.git" ]] || { echo "error: $APP_DIR is not a Git checkout" >&2; exit 1; }
[[ -f "$ENV_FILE" ]] || { echo "error: missing configuration: $ENV_FILE" >&2; exit 1; }

exec 9>/run/lock/vulnarchive-upgrade.lock
flock -n 9 || { echo "error: another VULNARCHIVE upgrade is running" >&2; exit 1; }

cd "$APP_DIR"
clean_build_artifacts() {
    local path
    local -a paths=("$APP_DIR/build")
    while IFS= read -r -d '' path; do
        paths+=("$path")
    done < <(find "$APP_DIR/src" -mindepth 1 -maxdepth 1 -type d -name '*.egg-info' -print0)

    for path in "${paths[@]}"; do
        [[ -e "$path" ]] || continue
        # Never remove the path if any file below it is tracked, even if a
        # future .gitignore rule accidentally classifies adjacent files.
        if [[ -n $(git ls-files -- "$path") ]]; then
            echo "error: refusing to remove tracked build path: $path" >&2
            exit 1
        fi
        rm -rf -- "$path"
    done
}

# Local package builds can leave these disposable artifacts behind. This works
# even while upgrading from a revision that did not ignore the artifacts yet.
clean_build_artifacts

# Only tracked modifications are unsafe. Other untracked operator files do not
# affect a fast-forward pull; Git itself still refuses an actual path collision.
if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "error: refusing to upgrade a checkout with modified tracked files" >&2
    git status --short >&2
    exit 1
fi

old_revision=$(git rev-parse HEAD)
echo "==> Current revision: $old_revision"
if (( PULL )); then
    echo "==> Updating checkout (fast-forward only)"
    git pull --ff-only
fi
new_revision=$(git rev-parse HEAD)
echo "==> Target revision:  $new_revision"

if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    echo "==> Creating virtual environment"
    "$PYTHON" -m venv "$VENV_DIR"
fi

# Test the target source before interrupting production. PYTHONPATH ensures the
# checkout is tested rather than the package currently installed in the venv.
echo "==> Running pre-deployment tests"
PYTHONPATH="$APP_DIR/src" "$VENV_DIR/bin/python" -m unittest discover -s tests -v
"$VENV_DIR/bin/python" -m compileall -q src

web_was_active=0
review_was_active=0
timer_was_active=0
systemctl is-active --quiet vulnarchive-web.service && web_was_active=1 || true
systemctl is-active --quiet vulnarchive-review.service && review_was_active=1 || true
systemctl is-active --quiet vulnarchive-sync.timer && timer_was_active=1 || true
services_stopped=0

recover_services() {
    exit_code=$?
    if (( exit_code != 0 && services_stopped )); then
        echo "ERROR: upgrade failed; attempting to restore previously active services" >&2
        (( web_was_active )) && systemctl start vulnarchive-web.service || true
        (( review_was_active )) && systemctl start vulnarchive-review.service || true
        (( timer_was_active )) && systemctl start vulnarchive-sync.timer || true
        echo "The checkout is at $(git rev-parse HEAD); previous revision was $old_revision." >&2
        echo "Use the backup reported above if application and database rollback is required." >&2
    fi
}
trap recover_services EXIT

echo "==> Stopping scheduled and active application processes"
systemctl stop vulnarchive-sync.timer
systemctl stop vulnarchive-sync.service
(( review_was_active )) && systemctl stop vulnarchive-review.service || true
(( web_was_active )) && systemctl stop vulnarchive-web.service || true
services_stopped=1

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
backup_dir="$BACKUP_ROOT/$timestamp-$old_revision"
install -d -m 0750 "$BACKUP_ROOT" "$backup_dir"
echo "==> Backup: $backup_dir"
install -m 0640 "$ENV_FILE" "$backup_dir/vulnarchive.env"
printf '%s\n' "$old_revision" >"$backup_dir/git-revision"
if [[ -f "$DB_FILE" ]]; then
    DB_SOURCE="$DB_FILE" DB_TARGET="$backup_dir/fd-sightings.sqlite" \
        "$VENV_DIR/bin/python" - <<'PY'
import os
import sqlite3

source = sqlite3.connect(f"file:{os.environ['DB_SOURCE']}?mode=ro", uri=True)
target = sqlite3.connect(os.environ["DB_TARGET"])
try:
    source.backup(target)
finally:
    target.close()
    source.close()
PY
    chmod 0640 "$backup_dir/fd-sightings.sqlite"
else
    echo "==> No existing SQLite database at $DB_FILE; skipping database backup"
fi

echo "==> Installing target revision into the virtual environment"
"$VENV_DIR/bin/python" -m pip install --no-deps --force-reinstall --no-build-isolation "$APP_DIR"
# setuptools may generate build/ and *.egg-info in the checkout. Do not leave
# them behind to surprise an older upgrade script or an operator's git status.
clean_build_artifacts

echo "==> Installing systemd units"
install -m 0644 deploy/vulnarchive-web.service deploy/vulnarchive-review.service \
    deploy/vulnarchive-sync.service deploy/vulnarchive-sync.timer /etc/systemd/system/
systemctl daemon-reload

# Opening the store applies idempotent SQLite migrations. plan-auto does not
# publish, reserve identifiers, or contact a write API.
echo "==> Applying store migrations and validating the publication plan"
runuser --user vulnarchive -- "$VENV_DIR/bin/fd-sightings" \
    --db "$DB_FILE" plan-auto --limit 1 >/dev/null

echo "==> Restarting previously active services"
(( web_was_active )) && systemctl start vulnarchive-web.service || true
(( review_was_active )) && systemctl start vulnarchive-review.service || true
(( timer_was_active )) && systemctl start vulnarchive-sync.timer || true

if (( web_was_active )); then
    echo "==> Checking local public service"
    for attempt in {1..20}; do
        if curl --silent --fail --max-time 2 http://127.0.0.1:8766/ >/dev/null 2>&1; then
            break
        fi
        if (( attempt == 20 )); then
            echo "error: public service health check failed" >&2
            systemctl --no-pager --full status vulnarchive-web.service >&2 || true
            journalctl --no-pager -u vulnarchive-web.service -n 30 >&2 || true
            exit 1
        fi
        sleep 1
    done
fi

services_stopped=0
echo "==> Upgrade complete: $old_revision -> $new_revision"
echo "==> Backup retained at: $backup_dir"
