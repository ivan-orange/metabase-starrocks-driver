(ns metabase.driver.starrocks.impersonation
  "Pure email->StarRocks-username derivation, injection-safe escaping, and the
   EXECUTE AS SQL builder (Phase 2). No JDBC, no defmethod — Phase 4 consumes this.

   Three public fns:
   - derive-username: Metabase email/login string -> lowercase StarRocks username
     or nil. Total (D-03): never throws; nil on no-`@`, empty prefix, or (Task 2)
     disallowed characters. Phase 4 hard-fails loudly (USR-03) on nil.
   - escape-username: quote-doubling (USR-02) — defense-in-depth on an
     already-validated username.
   - execute-as-sql: builds the literal EXECUTE AS \"<user>\" WITH NO REVERT
     (no trailing `;` — spike-proven single-statement form).
   - execute-as-error->humanized: pure error classifier (Phase 4, ERR-01/ERR-02).
     Maps a raw StarRocks EXECUTE AS failure message -> a humanized
     {:type <qp-keyword> :message <string>} (ERR-01 missing IMPERSONATE, ERR-02
     StarRocks < 2.4) or nil (caller rethrows a generic loud ex-info). Stays
     JDBC-free so it is unit-tested via `:test` without a live StarRocks."
  (:require
   [clojure.string :as str]))

(set! *warn-on-reflection* true)   ; house convention, even with no interop

(defn- allowed-username?
  "Defensive allowlist (D-06/D-07): true only when `s` is composed solely of
   `[a-z0-9._-]` AND contains at least one alphanumeric (rejects all-punctuation
   prefixes like `.`/`...`/`--`/`_`). Two predicates over one lookahead, per house
   style. Rejects (→ nil at the caller) every SQL-adjacent breakout char —
   `\"` `'` `` ` `` `\\` `;` `|` space — and all non-ASCII (homoglyph defense).
   Never mutates: a disallowed char rejects the whole username rather than
   stripping (a stripped identity could resolve to the WRONG StarRocks user)."
  [s]
  (boolean (and (re-matches #"[a-z0-9._-]+" s)
                (re-find    #"[a-z0-9]" s))))

(defn derive-username
  "Metabase email/login string -> lowercase StarRocks username, or nil.
   Total (D-03): nil on non-string input, no-`@` (D-04), empty prefix (D-04), or
   any character outside the defensive allowlist (D-06/D-07). Trims surrounding
   whitespace and lowercase-folds the prefix (D-05); splits on the FIRST `@`
   (D-04 multiple-`@`). This is the SINGLE nil-sentinel gate — `escape-username`
   stays a total string->string."
  [email]
  (when (string? email)
    (let [trimmed (str/trim email)]
      (when (str/includes? trimmed "@")             ; D-04: no `@` -> nil
        (let [prefix (-> (str/split trimmed #"@" 2) ; D-04: split on FIRST `@`
                         first
                         str/lower-case)]           ; D-05: lowercase-fold
          (when (and (seq prefix)                   ; D-04: empty prefix -> nil
                     (allowed-username? prefix))     ; D-06/D-07: allowlist -> nil
            prefix))))))

(defn escape-username
  "Quote-doubling (USR-02) — double any embedded `\"` so a crafted username cannot
   break out of the quoted identifier. Total string->string; no nil coercion
   (the builder's precondition guarantees a validated non-nil string reaches here)."
  [username]
  (str/replace username "\"" "\"\""))

(defn execute-as-sql
  "Build `EXECUTE AS \"<user>\" WITH NO REVERT` (no trailing `;` — spike-proven).
   Precondition forbids nil so no `(str nil)` -> \"null\" identity ever escapes."
  [username]
  {:pre [(string? username)]}
  (str "EXECUTE AS \"" (escape-username username) "\" WITH NO REVERT"))

(defn execute-as-error->humanized
  "Pure EXECUTE AS failure classifier (ERR-01/ERR-02, D-03). Given the raw
   StarRocks failure message `msg`, return a humanized
   `{:type <qp-keyword> :message <string>}` or nil.

   Ordering matters — check ERR-01 FIRST (RESEARCH § Error Surfacing ordering):
   - ERR-01 (`(?i)impersonate privilege`) is the live-verified, most-specific
     signal (verbatim §SC-4, SQLSTATE 42000). Per D-04 it is a SINGLE message —
     a privilege denial and a missing target user both resolve here; do NOT split
     into finer causes (that is v2 ERRX-01). Points at the README `GRANT
     IMPERSONATE` recipe.
   - ERR-02 (`(?i)syntax error|unexpected input|failed to parse|no viable
     alternative`) is the broad pre-2.4 parse heuristic. It is safe ONLY because
     the caller scopes it to the machine-generated EXECUTE AS statement (the
     user's own query runs later, outside that catch — T-04-06).
   - Any other message -> nil, so the caller rethrows a generic loud ex-info and
     NEVER continues as the base account (C-05).

   The `:type` keywords surface via `ex-message` regardless of whether they are
   registered QP error types, so they need not be pre-declared."
  [msg]
  (let [msg (if (string? msg) msg (str msg))]
    (cond
      (re-find #"(?i)impersonate privilege" msg)
      {:type    :qp/impersonation-privilege-missing
       :message (str "Per-user impersonation failed: the StarRocks connection "
                     "account lacks the IMPERSONATE privilege needed to run this "
                     "query as your StarRocks user. Grant it with `GRANT IMPERSONATE "
                     "ON USER '<user>'@'%' TO USER '<base-account>'@'%';` — see the "
                     "\"Per-User Impersonation\" section of the driver README.")}

      (re-find #"(?i)syntax error|unexpected input|failed to parse|no viable alternative" msg)
      {:type    :qp/impersonation-unsupported-version
       :message "StarRocks 2.4+ is required for per-user impersonation (EXECUTE AS)."}

      :else nil)))

;;; --------------------------------------------------------------------------
;;; Seam-B engagement disposition (04-03 CR-01, C-05 fail-closed)
;;; --------------------------------------------------------------------------

(defn impersonation-disposition
  "Pure, total decision fn — the unit-testable core of the CR-01 fail-closed
   Seam-B guard (C-05 zero-cross-user-leakage). Given the query-only flag
   `impersonating?` and the seam's `db-or-id-or-spec` argument, return exactly
   one keyword and NEVER throw:

   - `:pass-through` — `impersonating?` is falsey (the toggle-off / non-query
     path stays on the pooled `:sql-jdbc` account, SC3/IMP-04), OR impersonation
     is on but the toggle is provably, canonically OFF for this query (C-04):
     boolean `false`, the string `\"false\"`, `nil`, OR a `:details` map lacking
     `:enable-impersonation` entirely (the toggle reads `nil`).
   - `:impersonate` — `impersonating?` is truthy AND `db-or-id-or-spec` is a map
     carrying `:details` whose `:enable-impersonation` reads the canonical ON
     form: boolean `true` or the string `\"true\"`.
   - `:indeterminate` — `impersonating?` is truthy but the disposition cannot be
     read as a clean boolean, so the caller MUST hard-fail rather than guess.
     This covers TWO sub-cases:
     (a) `db-or-id-or-spec` is NOT a map-with-`:details` (an integer id, a
         pre-resolved spec lacking `:details`, or nil), so the toggle cannot be
         read to PROVE it is OFF; and
     (b) the toggle IS readable but is a truthy-but-non-canonical value
         (`\"TRUE\"`, `\"True\"`, `\"1\"`, `1`, `\"on\"`, `:true`, …) — the
         manifest declares `enable-impersonation` as `type: boolean`, so any
         value outside the exact ON/OFF sets is ambiguous. Silently reading it as
         either ON or OFF risks running on the wrong (base pooled) account — the
         exact cross-user leak this guard exists to prevent (CR-01, C-05,
         Pitfall 3). Seam B already hard-fails `:indeterminate`.

   Matching is EXACT (never case-folded): only boolean `true`/`false`, the
   strings `\"true\"`/`\"false\"`, and `nil` are legible; everything else is
   `:indeterminate`. Determinability is `(and (map? db-or-id-or-spec)
   (contains? db-or-id-or-spec :details))`; only when that holds do we read the
   toggle at all."
  [impersonating? db-or-id-or-spec]
  (if-not impersonating?
    :pass-through
    (if (and (map? db-or-id-or-spec)
             (contains? db-or-id-or-spec :details))
      (let [toggle (:enable-impersonation (:details db-or-id-or-spec))]
        (cond
          ;; canonical ON — engage EXECUTE AS
          (or (true? toggle) (= "true" toggle))   :impersonate
          ;; bounded, canonical OFF — stay on the pooled base account (nil also
          ;; covers a :details map with no :enable-impersonation key)
          (or (false? toggle) (= "false" toggle)
              (nil? toggle))                        :pass-through
          ;; anything else (truthy-but-non-canonical) — refuse to guess (C-05)
          :else                                     :indeterminate))
      :indeterminate)))

;;; --------------------------------------------------------------------------
;;; Identity normalization + case-insensitive match (04-03 WR-03, IMP-05)
;;; --------------------------------------------------------------------------

(defn normalize-user
  "Reduce a StarRocks identity string to a bare lowercase comparison key.
   StarRocks `current_user()` returns e.g. \"'alice'@'%'\", and on some
   deployments \"'default_cluster:alice'@'%'\" — strip the `@…` suffix, the
   surrounding quotes, AND a leading `<cluster>:` qualifier so a
   `default_cluster:` form does not false-mismatch (Pitfall 1), then
   `str/lower-case`-fold (WR-03 — a non-lowercase `current_user()` must still
   match the lowercase derived username) and trim. Pure and total: coerces any
   input to a string first, never throws."
  [raw]
  (-> (str raw)
      (str/replace #"@.*$" "")        ; drop @'%'
      (str/replace "'" "")            ; drop quotes
      (str/replace #"^[^:@']+:" "")   ; drop a leading "<cluster>:" qualifier
      (str/lower-case)                ; WR-03: case-fold both sides at the call site
      (str/trim)))

(defn identity-match?
  "Pure, total, case-insensitive identity comparison (WR-03): true iff `expected`
   and the raw `current_user()` string reduce to the SAME normalized key. A
   genuine different user still returns false (fail-closed preserved, IMP-05)."
  [expected raw-current-user]
  (= (normalize-user expected)
     (normalize-user raw-current-user)))
