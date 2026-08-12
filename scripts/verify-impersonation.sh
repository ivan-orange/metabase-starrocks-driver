#!/usr/bin/env bash
# Per-user impersonation end-to-end verification harness (Phase 5, D-03).
#
# Drives the ALREADY-SHIPPED Phase-4 `EXECUTE AS` impersonation seam through
# Metabase's HTTP API — the way Metabase itself drives it — and proves, live:
#   * VRF-01: zero cross-user leakage under StarRocks RBAC across two real
#     StarRocks identities (identity + stable/differs/proper-subset row scope).
#   * VRF-03: bounded StarRocks connection growth under ramped concurrency
#     (10 -> 50 -> 100 -> 200) at ~200-user target scale.
#   * D-10:   the humanized USR-03 and ERR-01 failures surface end-to-end.
# It touches NO driver source — the Clojure code under test is read-only (C-01).
#
# The harness reads every /api/dataset outcome from the JSON BODY
# (.status / .data.rows / .error), NEVER from the HTTP status code — /api/dataset
# returns HTTP 202 even on query failure. Every request body is built with
# `jq -nc --arg` (never string interpolation) so SQL/usernames cannot corrupt the
# request (V5 injection mitigation). Session tokens, passwords, and StarRocks row
# PII are NEVER echoed to stdout or the report (threat model T-05-01/T-05-02).
#
# Usage:
#   MB_URL=https://metabase.test.example \
#   MB_ADMIN_USER=admin@example.com MB_ADMIN_PASS='...' \
#   TEST_USER_PASS='...' SR_BASE_USER=metabase_base SR_BASE_PASS='...' \
#   bash scripts/verify-impersonation.sh
#
#   (MB_ADMIN_TOKEN may be supplied in place of MB_ADMIN_USER/MB_ADMIN_PASS.)
#
# Requires: curl, jq, mysql, a reachable TEST Metabase EE pod (MB_URL), an admin
#   session/token for user provisioning, and StarRocks base creds (must hold
#   IMPERSONATE) for the SHOW PROCESSLIST connection probe. This is a TEST-ONLY
#   harness: it provisions users and drives load — never point it at production.
#
# TLS note: like scripts/spike-build.sh, when the host routes traffic through a
# TLS-intercepting proxy (Cloudflare WARP / corporate MITM) this script exports
# the host's trusted root CAs from the macOS keychain and passes them to curl via
# --cacert. It NEVER uses `curl --insecure`/`-k`. Set VERIFY_SKIP_CA=1 to disable.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# --------------------------------------------------------------------------
# Config / environment (all inputs via env; ${VAR:-} guards, spike-build style)
# --------------------------------------------------------------------------
MB_URL="${MB_URL:-}"
MB_DB_NAME="${MB_DB_NAME:-starrocks}"          # Metabase DB name to target (engine=starrocks)
MB_ADMIN_USER="${MB_ADMIN_USER:-}"
MB_ADMIN_PASS="${MB_ADMIN_PASS:-}"
MB_ADMIN_TOKEN="${MB_ADMIN_TOKEN:-}"           # alternative to user/pass
MB_NATIVE_GROUP_ID="${MB_NATIVE_GROUP_ID:-}"   # permissions group id granting native-query access

TEST_USER_PASS="${TEST_USER_PASS:-}"           # harness-owned password for provisioned users

# The two mapped test users. Email prefix (lowercased) MUST equal the StarRocks
# username (C-04). Defaults map to rls-test-1m / rls-test-2m (D-04).
TEST_USER_A_EMAIL="${TEST_USER_A_EMAIL:-rls-test-1m@example.com}"
TEST_USER_B_EMAIL="${TEST_USER_B_EMAIL:-rls-test-2m@example.com}"

# D-10 error-path fixtures.
#   USR03: a Metabase user whose email-prefix maps to NO StarRocks user.
#   ERR01: a Metabase user whose email-prefix maps to a StarRocks target the base
#          account deliberately lacks IMPERSONATE on (the A7 throwaway fixture).
USR03_EMAIL="${USR03_EMAIL:-no-such-starrocks-user@example.com}"
ERR01_EMAIL="${ERR01_EMAIL:-}"

# Root/unfiltered RBAC baseline source (D-06). MUST be an identity/connection that
# sees the UNFILTERED row set — e.g. a second StarRocks DB connection with
# impersonation OFF, or an admin mapped to a StarRocks superuser. Defaults fall
# back to the admin token + primary DB (override when admin is itself scoped).
MB_BASELINE_TOKEN="${MB_BASELINE_TOKEN:-}"
MB_BASELINE_DB_ID="${MB_BASELINE_DB_ID:-}"

# StarRocks FE base creds for the read-only SHOW PROCESSLIST probe.
SR_FE_HOST="${SR_FE_HOST:-host.docker.internal}"   # 'localhost' when run on a bare host
SR_FE_PORT="${SR_FE_PORT:-9030}"
SR_BASE_USER="${SR_BASE_USER:-}"
SR_BASE_PASS="${SR_BASE_PASS:-}"

# Expected normalized StarRocks usernames, derived from the email prefixes (C-04).
EXPECT_USER_A="$(printf '%s' "${TEST_USER_A_EMAIL%%@*}" | tr '[:upper:]' '[:lower:]')"
EXPECT_USER_B="$(printf '%s' "${TEST_USER_B_EMAIL%%@*}" | tr '[:upper:]' '[:lower:]')"

# Runtime state
ADMIN_TOKEN=""
DB_ID=""
TOKEN_A=""
TOKEN_B=""
CURL_CA=()          # curl --cacert args (proxy-safe TLS); empty = system trust
CA_BUNDLE=""
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/verify-impersonation.XXXXXX")"
RESULTS_FILE="$TMP_ROOT/results.txt"
: > "$RESULTS_FILE"
OVERALL_OK=1

# --------------------------------------------------------------------------
# Cleanup (best-effort; never leak temp dirs or the exported CA bundle)
# --------------------------------------------------------------------------
cleanup() {
  [ -n "${TMP_ROOT:-}" ] && rm -rf "$TMP_ROOT" 2>/dev/null || true
  [ -n "${CA_BUNDLE:-}" ] && rm -f "$CA_BUNDLE" 2>/dev/null || true
}
trap cleanup EXIT

# --------------------------------------------------------------------------
# Reporting helpers (secret-free: only outcomes + counts, never tokens/PII)
# --------------------------------------------------------------------------
record() { printf '%s\n' "$1" >> "$RESULTS_FILE"; }
pass()   { printf 'PASS: %s\n' "$1"; record "PASS: $1"; }
note()   { printf 'NOTE: %s\n' "$1"; record "NOTE: $1"; }
fail()   { printf 'FAIL: %s\n' "$1" >&2; record "FAIL: $1"; OVERALL_OK=0; emit_report >&2; exit 1; }

emit_report() {
  printf '\n=========== verify-impersonation report ===========\n'
  cat "$RESULTS_FILE"
  if [ "$OVERALL_OK" -eq 1 ]; then
    printf '=========== VERDICT: PASS ===========\n'
  else
    printf '=========== VERDICT: FAIL ===========\n'
  fi
}

# --------------------------------------------------------------------------
# Preflight: dependencies + explicit-target guard (prohibition 3)
# --------------------------------------------------------------------------
require_deps() {
  local missing="" c
  for c in curl jq mysql; do
    command -v "$c" >/dev/null 2>&1 || missing="$missing $c"
  done
  [ -z "$missing" ] || fail "missing required tools:$missing (install them and re-run)"
}

guard_target() {
  # Never provision/drive an unknown endpoint. MB_URL must be explicitly set.
  [ -n "$MB_URL" ] || fail "MB_URL is unset — refusing to run. Set MB_URL to your TEST Metabase EE base URL (never production)."
  MB_URL="${MB_URL%/}"
  [ -n "$TEST_USER_PASS" ] || fail "TEST_USER_PASS is unset — required to provision and log in as the test users."
}

# --------------------------------------------------------------------------
# Proxy-safe TLS: export host-trusted root CAs (macOS keychain), pass via
# --cacert. NEVER curl --insecure (threat model T-05-05 / ASVS V6).
# --------------------------------------------------------------------------
setup_ca() {
  CURL_CA=()
  if [ "${VERIFY_SKIP_CA:-0}" != "1" ] && [ "$(uname -s)" = "Darwin" ]; then
    CA_BUNDLE="$(mktemp -t verify-host-ca.XXXXXX)"
    {
      security find-certificate -a -p /Library/Keychains/System.keychain 2>/dev/null || true
      security find-certificate -a -p "$HOME/Library/Keychains/login.keychain-db" 2>/dev/null || true
    } > "$CA_BUNDLE"
    if [ -s "$CA_BUNDLE" ]; then
      CURL_CA=(--cacert "$CA_BUNDLE")
      note "Injecting host-trusted root CAs into curl (proxy-safe TLS)."
    fi
  fi
}

# curl wrapper carrying the proxy-safe CA args (guarded for bash 3.2 empty arrays).
_curl() { curl "${CURL_CA[@]+"${CURL_CA[@]}"}" "$@"; }

# --------------------------------------------------------------------------
# Metabase auth helpers
# --------------------------------------------------------------------------
# mb_login <user> <pass> -> prints session token (.id). Never echoes the password.
mb_login() {
  local user="$1" pass="$2" resp token
  resp="$(_curl -s -X POST "$MB_URL/api/session" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc --arg u "$user" --arg p "$pass" '{username:$u,password:$p}')")"
  token="$(printf '%s' "$resp" | jq -r '.id // empty' 2>/dev/null)" \
    || fail "Metabase login returned a non-JSON response (proxy/gateway error, or MB_URL not a Metabase API?)."
  [ -n "$token" ] || fail "Metabase login failed (check credentials / password login enabled — not SSO-only)."
  printf '%s' "$token"
}

# mb_api <method> <path> [json-body] -> prints response body. Uses ADMIN_TOKEN.
mb_api() {
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    _curl -s -X "$method" "$MB_URL$path" \
      -H "X-Metabase-Session: $ADMIN_TOKEN" \
      -H 'Content-Type: application/json' \
      -d "$body"
  else
    _curl -s -X "$method" "$MB_URL$path" \
      -H "X-Metabase-Session: $ADMIN_TOKEN" \
      -H 'Content-Type: application/json'
  fi
}

admin_auth() {
  if [ -n "$MB_ADMIN_TOKEN" ]; then
    ADMIN_TOKEN="$MB_ADMIN_TOKEN"
  else
    [ -n "$MB_ADMIN_USER" ] && [ -n "$MB_ADMIN_PASS" ] \
      || fail "Set MB_ADMIN_TOKEN, or both MB_ADMIN_USER and MB_ADMIN_PASS (superuser for provisioning)."
    ADMIN_TOKEN="$(mb_login "$MB_ADMIN_USER" "$MB_ADMIN_PASS")"
  fi
  pass "admin authenticated for provisioning"
}

# --------------------------------------------------------------------------
# Provisioning (D-05): idempotent GET-then-POST; DB-id discovery
# --------------------------------------------------------------------------
find_db_id() {
  # Tolerate both the paged {data:[...]} and the bare-array shapes.
  mb_api GET "/api/database" \
    | jq -r --arg n "$MB_DB_NAME" \
        '[ (.data // .)[] | select(.engine=="starrocks" and .name==$n) | .id ] | first // empty'
}

resolve_db_id() {
  DB_ID="$(find_db_id)"
  [ -n "$DB_ID" ] || fail "No StarRocks database named '$MB_DB_NAME' found via /api/database (set MB_DB_NAME)."
  pass "resolved StarRocks database id for '$MB_DB_NAME'"
}

# ensure_user <email> <first> <last> -> prints Metabase user id. Idempotent.
ensure_user() {
  local email="$1" first="$2" last="$3" id body
  id="$(mb_api GET "/api/user?status=all" \
    | jq -r --arg e "$email" '[ (.data // .)[] | select(.email==$e) | .id ] | first // empty')"
  if [ -n "$id" ]; then
    # Best-effort reactivation in case a prior run deactivated the account.
    mb_api PUT "/api/user/$id/reactivate" >/dev/null 2>&1 || true
    printf '%s' "$id"
    return 0
  fi
  if [ -n "$MB_NATIVE_GROUP_ID" ]; then
    body="$(jq -nc --arg f "$first" --arg l "$last" --arg e "$email" \
      --arg p "$TEST_USER_PASS" --argjson g "[$MB_NATIVE_GROUP_ID]" \
      '{first_name:$f,last_name:$l,email:$e,password:$p,group_ids:$g}')"
  else
    body="$(jq -nc --arg f "$first" --arg l "$last" --arg e "$email" \
      --arg p "$TEST_USER_PASS" \
      '{first_name:$f,last_name:$l,email:$e,password:$p}')"
  fi
  id="$(mb_api POST "/api/user" "$body" | jq -r '.id // empty')"
  [ -n "$id" ] || fail "Failed to provision Metabase user (password complexity? admin not superuser?)."
  printf '%s' "$id"
}

# --------------------------------------------------------------------------
# Dataset helper — READ THE BODY, NOT THE HTTP CODE
# --------------------------------------------------------------------------
# run_native <token> <db_id> <sql> -> prints the JSON response body.
run_native() {
  local token="$1" db="$2" sql="$3"
  _curl -s -X POST "$MB_URL/api/dataset" \
    -H "X-Metabase-Session: $token" \
    -H 'Content-Type: application/json' \
    -d "$(jq -nc --argjson db "$db" --arg q "$sql" \
          '{database:$db, type:"native", native:{query:$q}}')"
}

# --------------------------------------------------------------------------
# Identity normalization — mirrors impersonation/normalize-user exactly:
# strip @-suffix, drop quotes, drop a leading "<cluster>:" qualifier, lowercase,
# trim. So "'default_cluster:RLS-Test-1m'@'%'" -> "rls-test-1m".
# --------------------------------------------------------------------------
normalize_user() {
  printf '%s' "${1:-}" \
    | sed -E "s/@.*$//" \
    | tr -d "'" \
    | sed -E "s/^[^:@]+://" \
    | tr '[:upper:]' '[:lower:]' \
    | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//'
}

# --------------------------------------------------------------------------
# StarRocks FE connection probe (reused by the VRF-03 ramp in Task 3).
# --------------------------------------------------------------------------
sr_processlist_count() {
  local n
  n="$(MYSQL_PWD="$SR_BASE_PASS" mysql -h "$SR_FE_HOST" -P "$SR_FE_PORT" -u "$SR_BASE_USER" \
        -N -B -e 'SHOW PROCESSLIST' 2>/dev/null | wc -l | tr -d '[:space:]')" || n=""
  [ -n "$n" ] || n=0
  printf '%s' "$n"
}

# --------------------------------------------------------------------------
# VRF-01 building blocks
# --------------------------------------------------------------------------
# Confirm the user can run native SQL at all (Pitfall 1 — native-query perm).
assert_select1() {
  local token="$1" db="$2" who="$3" body status
  body="$(run_native "$token" "$db" 'SELECT 1')"
  status="$(printf '%s' "$body" | jq -r '.status' 2>/dev/null)" \
    || fail "$who: non-JSON response from /api/dataset on the SELECT 1 gate (proxy/gateway error?)."
  [ "$status" = "completed" ] \
    || fail "SELECT 1 gate failed for $who — native-query permission missing on the target DB (set MB_NATIVE_GROUP_ID)."
  pass "native-query gate ok for $who"
}

# Assert current_user() (normalized) equals the expected StarRocks username.
assert_identity() {
  local token="$1" db="$2" expect="$3" who="$4" body status raw norm
  body="$(run_native "$token" "$db" 'SELECT current_user()')"
  status="$(printf '%s' "$body" | jq -r '.status' 2>/dev/null)" \
    || fail "identity probe for $who got a non-JSON response from /api/dataset (proxy/gateway error?)."
  if [ "$status" != "completed" ]; then
    fail "identity probe for $who did not complete (status=$status)"
  fi
  raw="$(printf '%s' "$body" | jq -r '.data.rows[0][0] // empty')"
  norm="$(normalize_user "$raw")"
  [ "$norm" = "$expect" ] \
    || fail "identity mismatch for $who: expected '$expect' but current_user() normalized to '$norm'"
  pass "identity: $who runs as StarRocks user '$expect'"
}

# The RBAC row-scope probe (D-04/D-06, VERIFIED Phase-1 baseline). DISTINCT so
# the comparison is over a set; never hard-code expected row values.
RLS_PROBE_SQL='SELECT DISTINCT merchant_id, psp FROM raw.payments'

# rowset_to_file <token> <db> <sql> <out> — canonicalize the DISTINCT rows into a
# sorted set file (D-06 ordering: sort so nondeterministic StarRocks row order
# never false-flags a stable set as unstable). Row PII stays in temp files under
# TMP_ROOT — never printed to the report (threat model T-05-02).
rowset_to_file() {
  local token="$1" db="$2" sql="$3" out="$4" body status
  body="$(run_native "$token" "$db" "$sql")"
  status="$(printf '%s' "$body" | jq -r '.status' 2>/dev/null)" \
    || fail "row-scope probe got a non-JSON response from /api/dataset (proxy/gateway error?)."
  [ "$status" = "completed" ] \
    || fail "row-scope probe did not complete (status=$status): $(printf '%s' "$body" | jq -r '.error // "unknown"')"
  printf '%s' "$body" | jq -rc '.data.rows[] | @json' | LC_ALL=C sort > "$out"
}

# Capture the root/unfiltered baseline set once (D-06 leg c reference).
capture_baseline() {
  local token="${MB_BASELINE_TOKEN:-$ADMIN_TOKEN}" db="${MB_BASELINE_DB_ID:-$DB_ID}"
  if [ -z "$MB_BASELINE_TOKEN" ]; then
    note "Baseline captured via the admin token — CONFIRM this identity sees the UNFILTERED set (set MB_BASELINE_TOKEN/MB_BASELINE_DB_ID otherwise)."
  fi
  rowset_to_file "$token" "$db" "$RLS_PROBE_SQL" "$TMP_ROOT/baseline.set"
  pass "captured root/unfiltered baseline ($(wc -l < "$TMP_ROOT/baseline.set" | tr -d ' ') distinct rows)"
}

# assert_rbac_invariant <token> <db> <expect> <slug> <label> — writes the
# identity's canonical set to $TMP_ROOT/<slug>.set and asserts the policy-agnostic
# D-06 invariant: (a) STABLE across turns, (c) proper SUBSET of the root baseline,
# plus per-query current_user() identity match. (b) DIFFERS is checked by caller.
assert_rbac_invariant() {
  local token="$1" db="$2" expect="$3" slug="$4" label="$5"
  local f1="$TMP_ROOT/${slug}.set" f2="$TMP_ROOT/${slug}.set2"
  rowset_to_file "$token" "$db" "$RLS_PROBE_SQL" "$f1"
  rowset_to_file "$token" "$db" "$RLS_PROBE_SQL" "$f2"
  # (a) STABLE — identical across repeated turns (already sorted).
  LC_ALL=C diff -q "$f1" "$f2" >/dev/null \
    || fail "$label row set is NOT stable across turns"
  pass "$label row set stable across turns ($(wc -l < "$f1" | tr -d ' ') rows)"
  # (c) proper SUBSET of the root baseline.
  local extra cA cB
  extra="$(LC_ALL=C comm -23 "$f1" "$TMP_ROOT/baseline.set" | wc -l | tr -d ' ')"
  [ "$extra" -eq 0 ] \
    || fail "$label sees $extra row(s) absent from the root baseline — RLS not enforced (leakage)"
  cA="$(wc -l < "$f1" | tr -d ' ')"
  cB="$(wc -l < "$TMP_ROOT/baseline.set" | tr -d ' ')"
  [ "$cA" -lt "$cB" ] \
    || fail "$label row set is not a PROPER subset of the baseline (count $cA >= baseline $cB)"
  pass "$label row set is a proper subset of the baseline ($cA < $cB)"
  # per-query identity match.
  assert_identity "$token" "$db" "$expect" "$label"
}

# assert_differs <slugA> <slugB> — leg (b): the two identities' sets are unequal
# even where their RLS policies overlap (no collision / merge).
assert_differs() {
  local a="$TMP_ROOT/$1.set" b="$TMP_ROOT/$2.set"
  if LC_ALL=C diff -q "$a" "$b" >/dev/null; then
    fail "user A and user B see IDENTICAL row sets — overlapping scopes collided"
  fi
  pass "user A and user B row sets differ (overlapping RLS never merges)"
}

# assert_error_contains <token> <db> <label> <needle> <error_type_fallback>
# Drives a D-10 failure live and asserts from the JSON BODY (never the HTTP code):
# .status=="failed" and the humanized .error substring; if EE redacts the text
# for non-admin users (A4), fall back to the driver .error_type. Surfaces A4 as a
# live-verify checkpoint in the report rather than a silent assumption.
assert_error_contains() {
  local token="$1" db="$2" label="$3" needle="$4" etype="$5" body status err etype_got
  body="$(run_native "$token" "$db" 'SELECT current_user()')"
  status="$(printf '%s' "$body" | jq -r '.status' 2>/dev/null)" \
    || fail "$label got a non-JSON response from /api/dataset (proxy/gateway error?)."
  [ "$status" = "failed" ] \
    || fail "$label expected a LOUD failure but status=$status (fail-loudly invariant — must never green)"
  err="$(printf '%s' "$body" | jq -r '.error // ""')"
  if printf '%s' "$err" | grep -qi "$needle"; then
    pass "$label surfaced the humanized message (contains '$needle')"
    return 0
  fi
  # A4 fallback — humanized .error may be redacted for non-admin users.
  etype_got="$(printf '%s' "$body" | jq -r '.error_type // ""')"
  if printf '%s' "$etype_got" | grep -q "$etype"; then
    note "A4 CHECKPOINT: EE redacted the humanized .error for $label — verified via .error_type='$etype'. Confirm redaction behavior on the first live run."
    pass "$label failed loudly with error_type '$etype' (A4 fallback)"
  else
    fail "$label surfaced neither '$needle' in .error nor '$etype' in .error_type"
  fi
}

# --------------------------------------------------------------------------
# VRF-03 — ramped load, connection non-accumulation gate, latency report
# --------------------------------------------------------------------------

# Aggregate whitespace-separated latency values on stdin -> "p50 p95 p99".
# sort + awk index-pick (never hand-rolled bash percentile math).
compute_percentiles() {
  sort -n | awk '
    { v[NR]=$1 }
    END{
      if (NR==0){ print "NA NA NA"; exit }
      i50=int((NR-1)*0.50)+1; i95=int((NR-1)*0.95)+1; i99=int((NR-1)*0.99)+1
      printf "%s %s %s\n", v[i50], v[i95], v[i99]
    }'
}

# ramp_one_level <level> <sample> — fire <level> concurrent /api/dataset requests
# spread across the two user tokens, sample PROCESSLIST before/peak/after, assert
# identity on a sampled subset under load, aggregate latency, and hard-gate on
# connection non-accumulation (D-09).
ramp_one_level() {
  local level="$1" sample="$2"
  local base peak after outdir jobs xpid cur
  base="$(sr_processlist_count)"
  outdir="$(mktemp -d "$TMP_ROOT/ramp-${level}.XXXXXX")"
  jobs="$outdir/jobs.txt"

  # Build the job list: each line "TOKEN OUTFILE MODE". The first <sample>
  # requests per token capture the JSON body (identity probe under load); the
  # rest discard the body and record only latency/status — the request COUNT and
  # load profile are identical either way (D-07/D-08/D-09 unchanged).
  # WR-08: keep session tokens out of argv and out of jobs.txt — write each token
  # to a 0600 header file (under the 0700 TMP_ROOT) and reference it by PATH. The
  # worker reads the header via `curl -H @file`, so tokens never appear in `ps`.
  local hdr_a="$outdir/hdr_a.http" hdr_b="$outdir/hdr_b.http"
  ( umask 077; printf 'X-Metabase-Session: %s\n' "$TOKEN_A" > "$hdr_a" )
  ( umask 077; printf 'X-Metabase-Session: %s\n' "$TOKEN_B" > "$hdr_b" )
  local i=1 count_a=0 count_b=0 hdr expect out mode
  while [ "$i" -le "$level" ]; do
    if [ $((i % 2)) -eq 1 ]; then
      hdr="$hdr_a"; expect="$EXPECT_USER_A"; count_a=$((count_a + 1))
      if [ "$count_a" -le "$sample" ]; then mode="id:$expect"; out="$outdir/id_${i}.id"; printf '%s' "$expect" > "$outdir/id_${i}.expect"
      else mode="load"; out="$outdir/req_${i}.load"; fi
    else
      hdr="$hdr_b"; expect="$EXPECT_USER_B"; count_b=$((count_b + 1))
      if [ "$count_b" -le "$sample" ]; then mode="id:$expect"; out="$outdir/id_${i}.id"; printf '%s' "$expect" > "$outdir/id_${i}.expect"
      else mode="load"; out="$outdir/req_${i}.load"; fi
    fi
    printf '%s %s %s\n' "$hdr" "$out" "$mode"
    i=$((i + 1))
  done > "$jobs"

  # Fire with bounded parallelism (xargs -P) + per-request temp files (no shared
  # append). Run in the background so PROCESSLIST peak can be sampled in flight.
  xargs -P "$level" -L1 sh -c '
    hdr="$1"; out="$2"; mode="$3"
    ca=""; [ -n "${VERIFY_CACERT:-}" ] && ca="--cacert ${VERIFY_CACERT}"
    case "$mode" in
      load)
        # Capture the JSON BODY (-o "$out") so success can be asserted, AND the
        # latency (-w to stdout -> "${out}.time"). HTTP 202 proves nothing here
        # (see header): failure is only observable in the body (WR-02). The
        # session token is read from the 0600 header file (-H @"$hdr"), never argv.
        curl -s $ca -o "$out" -w "%{time_total}\n" \
          -X POST "$MB_URL/api/dataset" \
          -H @"$hdr" -H "Content-Type: application/json" \
          -d "$LOAD_PAYLOAD" > "${out}.time" ;;
      id:*)
        curl -s $ca -X POST "$MB_URL/api/dataset" \
          -H @"$hdr" -H "Content-Type: application/json" \
          -d "$ID_PAYLOAD" > "$out" ;;
    esac
  ' _ < "$jobs" &
  xpid=$!

  peak="$base"
  while kill -0 "$xpid" 2>/dev/null; do
    cur="$(sr_processlist_count)"
    if [ "$cur" -gt "$peak" ]; then peak="$cur"; fi
    # WR-07: poll aggressively so fast levels do not complete between samples and
    # hide the true peak (a coarse poll can miss real growth -> false PASS).
    sleep "${VERIFY_POLL:-0.05}"
  done
  wait "$xpid" 2>/dev/null || true

  # Settle, then poll the post-drain count until it returns toward baseline
  # (WR-07: SHOW PROCESSLIST counts ALL cluster-wide FE sessions — the base-account
  # JDBC pool may warm/expand under load — so gate on a small tolerance with a
  # bounded drain-wait rather than byte-exact equality with the pre-test baseline).
  local settle="${DRAIN_SETTLE:-2}" tol="${DRAIN_TOLERANCE:-2}" waited=0 max_wait="${DRAIN_MAX_WAIT:-10}"
  sleep "$settle"
  after="$(sr_processlist_count)"
  while [ "$after" -gt $((base + tol)) ] && [ "$waited" -lt "$max_wait" ]; do
    sleep "$settle"
    waited=$((waited + settle))
    after="$(sr_processlist_count)"
  done

  # Identity UNDER concurrency (VRF-01/SC-1): assert every sampled body observed
  # the correct acting-user current_user(). Tolerate FE connection-cap hits at
  # high fan-out as a scaling finding (Pitfall 6), not a leak.
  local f norm raw status err id_checked=0
  for f in "$outdir"/id_*.id; do
    [ -e "$f" ] || continue
    id_checked=$((id_checked + 1))
    expect="$(cat "${f%.id}.expect")"
    status="$(jq -r '.status' < "$f" 2>/dev/null)" \
      || fail "level $level: non-JSON response body in a concurrent identity sample (proxy/gateway error?)."
    if [ "$status" != "completed" ]; then
      err="$(cat "$f" | jq -r '.error // ""')"
      if printf '%s' "$err" | grep -qi 'too many connections\|max_connections\|connection.*limit'; then
        note "level $level: hit a StarRocks connection cap (Pitfall 6 scaling finding, not a leak)."
        continue
      fi
      fail "level $level: sampled concurrent identity probe failed (status=$status)"
    fi
    raw="$(cat "$f" | jq -r '.data.rows[0][0] // empty')"
    norm="$(normalize_user "$raw")"
    [ "$norm" = "$expect" ] \
      || fail "level $level: CONCURRENT identity mismatch — expected '$expect' got '$norm' (leakage under load)"
  done
  # WR-03: the core under-load leakage assertion must actually run every level.
  if [ "$id_checked" -eq 0 ]; then
    fail "level $level: no concurrent-identity samples were validated — the core leakage check did not run"
  fi

  # Load-mode success ratio (WR-02): /api/dataset returns HTTP 202 even on query
  # failure, so a green connection gate is vacuous unless the bulk load queries
  # actually reached StarRocks. Assert a minimum success ratio, counting an
  # explicit FE connection-cap hit as an intended Pitfall-6 outcome (not a fail).
  local lf total_load=0 ok_load=0 lstatus lerr
  for lf in "$outdir"/req_*.load; do
    [ -e "$lf" ] || continue
    total_load=$((total_load + 1))
    lstatus="$(jq -r '.status // empty' < "$lf" 2>/dev/null || true)"
    if [ "$lstatus" = "completed" ]; then
      ok_load=$((ok_load + 1))
    else
      lerr="$(jq -r '.error // ""' < "$lf" 2>/dev/null || true)"
      if printf '%s' "$lerr" | grep -qi 'too many connections\|max_connections\|connection.*limit'; then
        ok_load=$((ok_load + 1))
      fi
    fi
  done
  if [ "$total_load" -gt 0 ]; then
    local min_pct="${VERIFY_LOAD_MIN_PCT:-80}" load_pct
    load_pct=$(( ok_load * 100 / total_load ))
    if [ "$load_pct" -lt "$min_pct" ]; then
      fail "level $level: only $ok_load/$total_load load requests completed (${load_pct}% < ${min_pct}%) — bulk load did not reach StarRocks; the connection gate would be vacuous (VRF-03)"
    fi
    pass "level $level: load success ratio $ok_load/$total_load (${load_pct}% >= ${min_pct}%)"
  fi

  # Latency percentiles (REPORTED only — no latency gate, D-09).
  local pcts p50 p95 p99
  pcts="$(cat "$outdir"/*.load.time 2>/dev/null | awk '{print $1}' | compute_percentiles)"
  p50="$(printf '%s' "$pcts" | awk '{print $1}')"
  p95="$(printf '%s' "$pcts" | awk '{print $2}')"
  p99="$(printf '%s' "$pcts" | awk '{print $3}')"

  # HARD GATE (D-09): peak bounded ~ baseline+level, AND post-drain == baseline.
  local margin="${PEAK_MARGIN:-5}"
  if [ "$peak" -gt $((base + level + margin)) ]; then
    fail "level $level: PROCESSLIST peak $peak exceeded baseline+level+margin ($((base + level + margin))) — unbounded connection growth"
  fi
  if [ "$after" -gt $((base + tol)) ]; then
    fail "level $level: connection ACCUMULATION — post-drain $after exceeds baseline $base + tolerance $tol (impersonated sessions leaked)"
  fi
  pass "level $level: connections base=$base peak=$peak after=$after (bounded, drained); latency p50/p95/p99=${p50}/${p95}/${p99}s"
}

run_ramp() {
  [ -n "$SR_BASE_USER" ] && [ -n "$SR_BASE_PASS" ] \
    || fail "SR_BASE_USER and SR_BASE_PASS are required for the VRF-03 SHOW PROCESSLIST probe."
  ulimit -n "${VERIFY_ULIMIT:-4096}" 2>/dev/null || true

  # Build the payloads once (jq -nc — never string interpolation) and export the
  # scalars the xargs workers need (header-file PATHS travel per-line; the tokens
  # themselves live only in 0600 files, never in argv or the environment — WR-08).
  local LOAD_PAYLOAD ID_PAYLOAD
  LOAD_PAYLOAD="$(jq -nc --argjson db "$DB_ID" --arg q 'SELECT current_user()' \
    '{database:$db,type:"native",native:{query:$q}}')"
  ID_PAYLOAD="$LOAD_PAYLOAD"
  export MB_URL LOAD_PAYLOAD ID_PAYLOAD
  if [ -n "${CA_BUNDLE:-}" ]; then export VERIFY_CACERT="$CA_BUNDLE"; fi

  note "VRF-03 ramp starting — note the FE max_connections / per-user cap; a cap hit at 200 is a scaling finding (Pitfall 6), not a leak."
  local sample="${VERIFY_ID_SAMPLE:-2}" LEVEL
  case "$sample" in
    ''|*[!0-9]*) fail "VERIFY_ID_SAMPLE must be a non-negative integer (got '$sample')." ;;
  esac
  [ "$sample" -ge 1 ] \
    || fail "VERIFY_ID_SAMPLE must be >= 1 (got '$sample') — the concurrent-identity leakage check must never be silently disabled."
  for LEVEL in 10 50 100 200; do
    ramp_one_level "$LEVEL" "$sample"
  done
  pass "VRF-03: connection non-accumulation gate held across all ramp levels"
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
main() {
  require_deps
  guard_target
  setup_ca
  admin_auth
  resolve_db_id

  # Provision + log in as test user A, then drive the single tracer path:
  # admin login -> ensure user A -> discover db id -> /api/dataset
  # SELECT current_user() -> normalized identity assertion.
  # --- Provision + log in as both mapped test users (idempotent, D-05) ---
  ensure_user "$TEST_USER_A_EMAIL" "RLS" "TestA" >/dev/null
  ensure_user "$TEST_USER_B_EMAIL" "RLS" "TestB" >/dev/null
  TOKEN_A="$(mb_login "$TEST_USER_A_EMAIL" "$TEST_USER_PASS")"
  TOKEN_B="$(mb_login "$TEST_USER_B_EMAIL" "$TEST_USER_PASS")"
  assert_select1 "$TOKEN_A" "$DB_ID" "user A"
  assert_select1 "$TOKEN_B" "$DB_ID" "user B"

  # --- VRF-01: identity + D-06 RBAC invariant across two identities ---
  assert_identity "$TOKEN_A" "$DB_ID" "$EXPECT_USER_A" "user A"
  assert_identity "$TOKEN_B" "$DB_ID" "$EXPECT_USER_B" "user B"
  capture_baseline
  assert_rbac_invariant "$TOKEN_A" "$DB_ID" "$EXPECT_USER_A" "userA" "user A"
  assert_rbac_invariant "$TOKEN_B" "$DB_ID" "$EXPECT_USER_B" "userB" "user B"
  assert_differs "userA" "userB"

  # --- D-10: drive USR-03 + ERR-01 live, assert from the JSON body ---
  ensure_user "$USR03_EMAIL" "No" "Mapping" >/dev/null
  local usr03_token
  usr03_token="$(mb_login "$USR03_EMAIL" "$TEST_USER_PASS")"
  assert_error_contains "$usr03_token" "$DB_ID" "USR-03" \
    "cannot determine your StarRocks identity" "impersonation-no-identity"

  if [ -n "$ERR01_EMAIL" ]; then
    ensure_user "$ERR01_EMAIL" "No" "Impersonate" >/dev/null
    local err01_token
    err01_token="$(mb_login "$ERR01_EMAIL" "$TEST_USER_PASS")"
    assert_error_contains "$err01_token" "$DB_ID" "ERR-01" \
      "IMPERSONATE privilege" "impersonation-privilege-missing"
  else
    note "ERR-01 skipped — set ERR01_EMAIL (prefix = a StarRocks user the base account lacks IMPERSONATE on, the A7 fixture) to drive it live."
  fi

  # --- VRF-03: ramped concurrency + connection non-accumulation gate ---
  run_ramp

  emit_report
}

main "$@"
