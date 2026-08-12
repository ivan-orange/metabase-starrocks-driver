# Metabase StarRocks Driver

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Metabase](https://img.shields.io/badge/Metabase-v0.50+-blue.svg)](https://www.metabase.com/)
[![StarRocks](https://img.shields.io/badge/StarRocks-v3.2+-green.svg)](https://www.starrocks.io/)

A community Metabase driver for [StarRocks](https://www.starrocks.io/) that fixes MySQL protocol compatibility issues and adds proper multi-catalog support.

> **This fork** adds **[Per-User Impersonation](#per-user-impersonation)** — a logged-in Metabase user's queries execute under their own StarRocks identity (via `EXECUTE AS`), so StarRocks RBAC enforces per-user data access. Verified end-to-end live against **Metabase Enterprise v1.61.1 + StarRocks (RBAC)** — `VERDICT: PASS` (zero cross-user leakage; bounded, drained connections under a 10→200 concurrency ramp). See [Per-User Impersonation](#per-user-impersonation).

## Why This Driver?

Metabase's built-in MySQL driver doesn't work properly with StarRocks because:

1. **`SHOW GRANTS FOR CURRENT_USER` is unsupported** — StarRocks uses a different privilege system than MySQL, causing metadata sync to fail with:
   ```
   No viable statement for input 'SHOW GRANTS FOR CURRENT_USER'
   ```

2. **Multi-catalog support** — StarRocks external catalogs (Hive, Iceberg, etc.) require `catalog.database` format which the MySQL driver doesn't handle well.

This driver extends Metabase's `sql-jdbc` driver directly, bypassing the problematic MySQL-specific code while maintaining full query compatibility.

## Installation

### Option 1: Download Pre-built JAR

Download the latest `starrocks.metabase-driver-vX.X.X.jar` from the [Releases](../../releases) page — this is the impersonation-capable build. For example, `v1.1.0`:

```
https://github.com/ivan-orange/metabase-starrocks-driver/releases/download/v1.1.0/starrocks.metabase-driver-v1.1.0.jar
```

### Option 2: Build from Source

```bash
# Install Clojure CLI (macOS) + a JDK (11-21)
brew install clojure/tools/clojure temurin

# Clone and build
git clone https://github.com/ivan-orange/metabase-starrocks-driver.git
cd metabase-starrocks-driver
clojure -T:build uber

# Output: target/starrocks.metabase-driver.jar
```

### Deploy the Driver

Copy the JAR to your Metabase plugins directory:

```bash
# Docker
docker cp starrocks.metabase-driver.jar metabase:/plugins/

# Local installation
cp starrocks.metabase-driver.jar /path/to/metabase/plugins/

# Kubernetes
kubectl cp starrocks.metabase-driver.jar <namespace>/<pod>:/plugins/
```

Then restart Metabase to load the driver.

#### Kubernetes / Helm — auto-fetch on pod start

To make Metabase load this driver **by default** on every (re)start, mount an
empty `/plugins` volume and fetch the release JAR with an init container. With
the [pmint93 Metabase Helm chart](https://github.com/pmint93/helm-charts) this is
a values snippet (works the same under Argo CD):

```yaml
image:
  repository: metabase/metabase-enterprise
  tag: v1.61.1.x
extraEnv:
  - name: MB_PLUGINS_DIR
    value: "/plugins"
extraVolumes:
  - name: mb-plugins
    emptyDir: {}
extraVolumeMounts:
  - name: mb-plugins
    mountPath: /plugins
extraInitContainers:
  - name: fetch-starrocks-driver
    image: curlimages/curl:latest
    command:
      - sh
      - -c
      - "curl -fSL -o /plugins/starrocks.metabase-driver.jar https://github.com/ivan-orange/metabase-starrocks-driver/releases/download/v1.1.0/starrocks.metabase-driver-v1.1.0.jar"
    volumeMounts:
      - name: mb-plugins
        mountPath: /plugins
```

Use `strategy.type: Recreate` so the init container re-runs and re-fetches the
JAR on every rollout. (Add `-k` to the `curl` only if your cluster egress goes
through a TLS-intercepting proxy; prefer mounting the proxy CA over disabling
verification.)

## Requirements

- **Metabase**: v0.50+ (tested with v0.57)
- **StarRocks**: v3.2+ (for external catalog support)
- **Java**: JDK 11-21 (for building from source)

## Configuration

1. Go to **Admin → Databases → Add Database**
2. Select **"StarRocks"** from the database type dropdown
3. Configure the connection:

| Field | Description | Example |
|-------|-------------|---------|
| Host | StarRocks FE hostname | `starrocks-fe.example.com` |
| Port | MySQL protocol port | `9030` |
| Catalog | StarRocks catalog name | `default_catalog` |
| Database | Database within catalog (optional) | `my_database` |
| Username | StarRocks user | `admin` |
| Password | User password | `••••••••` |

### Catalog Examples

- **Internal catalog**: `default_catalog`
- **Hive catalog**: `hive_catalog`
- **Iceberg/Polaris catalog**: `iceberg_catalog`

> **Tip**: Leave the **Database** field empty to see all databases in the catalog.

## Per-User Impersonation

When enabled, every query a Metabase user runs is executed under that user's **own StarRocks identity** (via StarRocks' native `EXECUTE AS "<user>" WITH NO REVERT`) instead of the shared connection account. StarRocks — not Metabase — then enforces that user's data-access permissions. Impersonation is strictly **opt-in** (default OFF) and configured per StarRocks database.

### Prerequisites

- **Metabase Enterprise/Pro** — the impersonation policy/UI surface is Enterprise/Pro-gated in Metabase core; the feature is only meaningfully exercised on EE/Pro.
- **StarRocks 2.4+** — `EXECUTE AS <user> WITH NO REVERT` (the per-user impersonation primitive this driver uses) requires StarRocks v2.4 or later.

### Grant the IMPERSONATE privilege

The base connection account (the StarRocks user configured in the database connection form) must be allowed to impersonate each target user. Grant the **least-privilege** per-user grant on the base account:

```sql
-- Grant the base connection account the right to impersonate each target user:
GRANT IMPERSONATE ON USER 'test.user'@'%' TO USER 'metabase_base'@'%';
-- ...repeat once per target StarRocks user.
```

Alternatively, a **StarRocks superuser holds `IMPERSONATE` implicitly** and needs no explicit grant — but prefer the per-user grants above so the base account can impersonate only the intended users.

If the base account lacks `IMPERSONATE` on a target user, the query fails with `Access denied; you need ... the IMPERSONATE privilege(s) on USER ...` — it never silently runs as the base account.

### Username mapping

StarRocks usernames **MUST equal the Metabase login's email prefix, lowercased**. The driver derives the StarRocks username from the logged-in user's email by taking everything before the first `@` and lowercasing it. Provision your StarRocks users to match:

| Metabase login (email)    | StarRocks username to provision                                  |
|---------------------------|------------------------------------------------------------------|
| `Test.User@example.com`  | `test.user` (prefix before `@`, lowercased)                     |
| `test.user@example.com`  | `test.user`                                                     |
| `bob@x.com`               | `bob`                                                            |
| `admin` (no `@`)          | unresolvable — the query hard-fails and never runs as the base account |

StarRocks usernames are **case-sensitive**, so always provision them lowercase to match the derived name. A login with no `@`, an empty prefix, or characters outside the `[a-z0-9._-]` allowlist is unresolvable: the query hard-fails loudly rather than falling back to the shared base/service account.

### Enable the toggle

No driver source access is needed — the toggle lives in the connection form:

1. Go to **Admin → Databases** and open your **StarRocks** database (or add a new one).
2. In the connection form, find **"Enable per-user impersonation (EXECUTE AS)"** (`enable-impersonation`). It is **OFF by default**.
3. Turn it **on** and save.

With the toggle on, every query a Metabase user runs executes under that user's own StarRocks identity.

### Reconciliation with Metabase's native impersonation

> Note: Because this driver declares the `connection-impersonation` feature, Metabase Enterprise/Pro will show a native **Impersonation** option for StarRocks under **Admin > Permissions > Data**. **Do not configure a native impersonation policy** for StarRocks. This driver enforces per-user identity through the connection toggle above (email-derived `EXECUTE AS`), not through Metabase's attribute-to-role mechanism. Leaving the native policy unconfigured keeps it dormant; configuring one would activate a separate role-setting path this driver deliberately does not use.

### Pre-release verification

Before shipping any release that touches the impersonation code path, run the re-runnable end-to-end verification harness `scripts/verify-impersonation.sh`. It drives the shipped `EXECUTE AS` seam through Metabase's HTTP API — the way Metabase itself drives it — against a **TEST** Metabase EE instance (never production), and fails loudly if the guarantees below no longer hold.

1. Provide its inputs by environment variable (names only — never commit or echo the secret values):
   - `MB_URL` — base URL of the **test** Metabase EE instance.
   - An admin credential for user provisioning: either `MB_ADMIN_USER` + `MB_ADMIN_PASS`, or `MB_ADMIN_TOKEN`.
   - `TEST_USER_PASS` — the harness-owned password for the provisioned test users.
   - StarRocks base creds (must hold `IMPERSONATE`): `SR_BASE_USER` + `SR_BASE_PASS`, used for the read-only `SHOW PROCESSLIST` connection probe.

   ```bash
   MB_URL=https://metabase.test.example \
   MB_ADMIN_USER=admin@example.com MB_ADMIN_PASS='...' \
   TEST_USER_PASS='...' SR_BASE_USER=metabase_base SR_BASE_PASS='...' \
   bash scripts/verify-impersonation.sh
   ```

2. Confirm the run ends in `VERDICT: PASS`. The harness proves, live:
   - **VRF-01 — zero cross-user leakage.** Every query's `current_user()` matches the acting user, and each user's RLS row set is stable across turns, differs from the other user's, and is a proper subset of the root/unfiltered baseline — under both sequential and concurrent load.
   - **VRF-03 — bounded connections under load.** Under a 10 → 50 → 100 → 200 concurrency ramp, StarRocks connection count stays bounded and returns to the pre-test baseline after each level drains (no impersonated sessions leaked); per-query latency p50/p95/p99 is reported (observed, not gated).

3. The harness also asserts the humanized USR-03 ("cannot determine your StarRocks identity") and ERR-01 (the `IMPERSONATE privilege` failure, consistent with the wording above) failures surface end-to-end on a real failing switch. ERR-02 (`StarRocks 2.4+ required`) is **not** reproducible on the 2.4+ test env, so it is not driven live here — it stays covered by the Phase-4 unit test.

### Verification status

Last verified live on **Metabase Enterprise v1.61.1 + StarRocks (RBAC)**: `VERDICT: PASS` — correct per-user identity for two mapped users, zero cross-user RLS leakage, the humanized USR-03 error surfaced to a non-admin user, and connections bounded and drained back to baseline under a 10→50→100→200 concurrency ramp (peak 23 → drained to baseline at level 200).

**Known harness caveats** — the driver itself is unaffected; these are current limits of `scripts/verify-impersonation.sh` to be aware of when running it:

- The "unfiltered" RLS baseline is read through Metabase's native-query result cap (2000 rows). On a probe table with more than 2000 distinct rows the baseline is truncated, which can produce a false leakage failure — bound the probe to a known small row set when validating large tables.
- Point the connection probe at the StarRocks FE over **TCP**: set `SR_FE_HOST=127.0.0.1` (not `localhost`). The MySQL client treats `-h localhost` as a Unix socket and ignores the port, so the probe reads **0** connections and the VRF-03 gate can pass vacuously. Always confirm the reported `SHOW PROCESSLIST` baseline is **non-zero** before trusting a VRF-03 pass.
- To actually exercise the USR-03 "cannot determine your StarRocks identity" path, use a login whose email prefix is *unmappable* (contains a character outside `[a-z0-9._-]`, e.g. `user+x@example.com`). A valid-but-nonexistent StarRocks user instead triggers the generic "user not found" failure.

## Limitations

- Foreign key relationships are not supported (StarRocks limitation)
- Some advanced MySQL features may not be available
- **Per-user impersonation** maps the Metabase email prefix → StarRocks username (lowercased) only — there is no attribute-override or fallback mapping; an unmappable login hard-fails rather than running as the base account.
- **ERR-02** (StarRocks < 2.4, which lacks `EXECUTE AS`) is caught and humanized, but is not exercised live on 2.4+ test environments.

## Project Structure

```
metabase-starrocks-driver/
├── deps.edn                         # Dependencies & build config
├── build.clj                        # Build script
├── src/metabase/driver/
│   └── starrocks.clj                # Driver implementation
├── resources/
│   ├── metabase-plugin.yaml         # Plugin manifest
│   └── metabase_driver/starrocks/
│       └── icon.svg                 # Driver icon
└── docs/
    └── metabase-infrastructure.md   # Deployment notes
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

1. Clone the repository
2. Install [Clojure CLI tools](https://clojure.org/guides/install_clojure)
3. Make your changes in `src/metabase/driver/starrocks.clj`
4. Build and test: `clojure -T:build uber`

## Releases

This project uses [semantic versioning](https://semver.org/). Releases are automated via GitHub Actions. The current impersonation release is **`v1.1.0`**.

To cut a new release, push a `v*` tag:

```bash
git tag v1.1.1
git push origin v1.1.1
```

This triggers the **Build and Release** workflow (`.github/workflows/release.yml`), which builds the uber JAR and creates a GitHub release with the artifact attached (e.g., `starrocks.metabase-driver-v1.1.1.jar`).

## Troubleshooting

### Connection Failed

- Verify StarRocks FE is accessible on the MySQL protocol port (default: 9030)
- Check firewall rules allow connections from Metabase
- Ensure the user has appropriate permissions

### Tables Not Showing

- Verify the catalog name is correct
- Check that the user has `SELECT` privileges on the tables
- Try leaving the Database field empty to scan all databases

### Sync Errors

- This driver bypasses `SHOW GRANTS` — if you see grant-related errors, ensure you're using this driver (not MySQL)

## License

This project is licensed under the Apache License 2.0 — see the [LICENSE](LICENSE) file for details.

## Related Projects

- [Metabase](https://github.com/metabase/metabase) — The open source BI tool
- [StarRocks](https://github.com/StarRocks/starrocks) — The analytics database
