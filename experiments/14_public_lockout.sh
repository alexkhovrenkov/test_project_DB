#!/bin/bash
# Experiment 14: the PUBLIC hard lockout, and how to get back in.
#
#   make lockout            (or: bash experiments/14_public_lockout.sh)
#
# A DENY given to PUBLIC applies to every account, the administrator included.
# The DENY reference warns that denying UPDATE on mysql.global_priv to PUBLIC
# removes even the normal recovery path (REVOKE DENY ... FROM PUBLIC), and that
# recovery then means deleting the PUBLIC row from mysql.global_priv,
# FLUSH PRIVILEGES and reconnecting.
#
# This must never run against the project's server, so it starts its own
# disposable server: a separately named container and volume (no published
# port, no TLS needed), removed again at the end, also on failure.
#
#   Part 1  DENY UPDATE ON *.* TO PUBLIC, then the documented recovery.
#   Part 2  DENY UPDATE, DELETE ON *.* TO PUBLIC: the documented recovery is
#           closed too; recovery needs a restart with --skip-grant-tables.
#
# Every step prints the SQL, the expected and the actual result, and PASS or
# FAIL; the script exits non-zero if any step fails. All SQL is fixed text.

set -euo pipefail

IMAGE="${MARIADB_IMAGE:-quay.io/mariadb-foundation/mariadb-devel@sha256:ed1087249cadb93623dd3b11258ea9790ad8f49c328dae5a5ef726ff1cea2931}"
NAME="university-lockout-$$"
VOLUME="$NAME-data"
FAILED=0
STEP=0

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker volume rm "$VOLUME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

start_server() {   # start_server [extra mariadbd options...]
    docker run -d --name "$NAME" -v "$VOLUME:/var/lib/mysql" \
        -e MARIADB_ALLOW_EMPTY_ROOT_PASSWORD=1 -e MARIADB_ROOT_HOST=localhost \
        "$IMAGE" "$@" >/dev/null
    # The temporary init server logs "port: 0"; the real server "port: 3306".
    for _ in $(seq 1 60); do
        if docker logs "$NAME" 2>&1 | grep -q "mysqld.sock.  port: 3306"; then
            return 0
        fi
        sleep 2
    done
    echo "ERROR: disposable server did not start" >&2
    docker logs "$NAME" >&2
    exit 1
}

stop_server() {
    docker stop "$NAME" >/dev/null
    docker rm "$NAME" >/dev/null
}

# step "<why>" "<expected: ok | ERROR nnnn>" "<sql>"
# Runs the SQL as root (unix_socket) in a NEW client session and checks the result.
step() {
    local why="$1" expected="$2" sql="$3" output actual detail verdict
    STEP=$((STEP + 1))
    detail=""
    if output=$(docker exec -i "$NAME" mariadb --protocol=socket -uroot --batch <<<"$sql" 2>&1); then
        actual="ok"
    else
        detail=$(grep '^ERROR' <<<"$output" | head -1 | sed 's/ at line [0-9]*//')
        actual=$(grep -o 'ERROR [0-9]*' <<<"$output" | head -1)
        actual="${actual:-failed}"
    fi
    if [ "$actual" = "$expected" ]; then verdict=PASS; else verdict=FAIL; FAILED=$((FAILED + 1)); fi
    echo
    echo "Step $STEP  user: root@localhost (new session)"
    echo "    SQL      $sql"
    echo "    Expected $expected"
    echo "    Actual   ${detail:-$actual}"
    echo "    Result   $verdict"
    echo "    Why      $why"
}

echo "=============================================================================="
echo " Experiment 14: PUBLIC hard lockout and recovery (disposable server $NAME)"
echo "=============================================================================="

echo; echo "--- Part 1: DENY UPDATE ON *.* TO PUBLIC ---"
start_server
step "Baseline: root can write." ok \
     "CREATE DATABASE lab; CREATE TABLE lab.t (id INT); INSERT INTO lab.t VALUES (1); UPDATE lab.t SET id = 2;"
step "Deny UPDATE on everything to PUBLIC - that includes root. In the SAME session the UPDATE still works (privileges were read at login) ..." ok \
     "DENY UPDATE ON *.* TO PUBLIC; UPDATE lab.t SET id = 3;"
step "... but every NEW session of root is refused." "ERROR 1142" \
     "UPDATE lab.t SET id = 4;"
step "The normal recovery path is closed: REVOKE DENY ... FROM PUBLIC needs UPDATE on mysql.global_priv. Note the misleading code: 1045 'Access denied ... (using password: NO)' reads like a failed LOGIN." "ERROR 1045" \
     "REVOKE DENY UPDATE ON *.* FROM PUBLIC;"
step "Editing the privilege table directly is UPDATE as well." "ERROR 1142" \
     "UPDATE mysql.global_priv SET Priv = '{}' WHERE User = 'PUBLIC';"
step "Documented recovery: DELETE was never denied - remove PUBLIC's row and reload the privilege tables." ok \
     "DELETE FROM mysql.global_priv WHERE User = 'PUBLIC'; FLUSH PRIVILEGES;"
step "A new session can write again." ok \
     "UPDATE lab.t SET id = 5;"
stop_server
docker volume rm "$VOLUME" >/dev/null

echo; echo "--- Part 2: DENY UPDATE, DELETE ON *.* TO PUBLIC ---"
start_server
step "Baseline." ok \
     "CREATE DATABASE lab; CREATE TABLE lab.t (id INT); INSERT INTO lab.t VALUES (1);"
step "Now deny DELETE too." ok \
     "DENY UPDATE, DELETE ON *.* TO PUBLIC;"
step "The documented recovery is closed as well: root cannot delete PUBLIC's row." "ERROR 1142" \
     "DELETE FROM mysql.global_priv WHERE User = 'PUBLIC';"
step "Nothing an account can do over SQL lifts it." "ERROR 1045" \
     "REVOKE DENY UPDATE, DELETE ON *.* FROM PUBLIC;"
echo
echo "Restarting the server with --skip-grant-tables (needs access to the server itself, not just SQL) ..."
stop_server
start_server --skip-grant-tables
step "Without privilege checks, delete PUBLIC's row." ok \
     "DELETE FROM mysql.global_priv WHERE User = 'PUBLIC';"
echo
echo "Restarting normally ..."
stop_server
start_server
step "Back to normal: root can write again." ok \
     "UPDATE lab.t SET id = 2; DELETE FROM lab.t;"

echo
echo "Security implication: a PUBLIC DENY can lock out every administrator. If it also covers DELETE (or"
echo "the mysql schema), only someone who can restart the server with --skip-grant-tables gets back in."
echo
echo "-> 14_public_lockout.sh: $((STEP - FAILED)) passed, $FAILED failed"
[ "$FAILED" -eq 0 ]
