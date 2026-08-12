(ns metabase.driver.starrocks.impersonation-test
  "VRF-02 edge matrix for the pure derivation/escape/SQL-builder logic.
   Every CONTEXT row plus the four RESEARCH gap rows (dot-only, non-ASCII,
   backslash, all-whitespace/nil) is an explicit, checkable assertion."
  (:require
   [clojure.test :refer [are deftest is testing]]
   [metabase.driver.starrocks.impersonation :as imp]))

(deftest derive-username-test
  ;; Matrix rows 1-9, 11-14 (row 10 escape + row 15 builder live below in isolation).
  (are [in out] (= out (imp/derive-username in))
    ;; Row 1  normal dotted prefix (dot survives allowlist)
    "test.user@example.com" "test.user"
    ;; Row 2  multiple-@ -> everything before the FIRST @
    "a@b@c.com"              "a"
    ;; Row 3  no-@ bare login -> nil
    "admin"                  nil
    ;; Row 4  empty prefix -> nil
    "@x.com"                 nil
    ;; Row 4b trim-then-empty prefix -> nil
    "  @x.com"               nil
    ;; Row 5  trim surrounding whitespace
    "  bob@x.com  "          "bob"
    ;; Row 6  lowercase-fold
    "Ivan@a.com"             "ivan"
    ;; Row 8  embedded " -> nil (allowlist rejects before any escaping fires)
    "iv\"an@x.com"           nil
    ;; Row 9  disallowed pipe -> nil
    "bad|name@x.com"         nil
    ;; Row 11 all-punctuation prefix -> nil (>=1-alphanumeric guard)
    ".@x.com"                nil
    "...@x.com"              nil
    ;; Row 12 non-ASCII / EAI local-part -> nil (ASCII-only allowlist; homoglyph defense)
    "résumé@x.com"           nil
    "用户@x.com"              nil
    ;; Row 13 embedded backslash (escape-vector char) -> nil
    "a\\b@x.com"             nil
    ;; Row 14 all-whitespace / empty / non-string -> nil (total, never throws)
    "   "                    nil
    ""                       nil
    nil                      nil))

(deftest derive-username-collision-test
  ;; Row 7  collision: two distinct logins derive to the SAME username by design
  ;;        (D-05, no dedupe) — identical output IS the defined behavior.
  (testing "distinct logins collide to identical derived username (no dedupe)"
    (is (= "ivan" (imp/derive-username "Ivan@a.com")))
    (is (= "ivan" (imp/derive-username "ivan@b.com")))
    (is (= (imp/derive-username "Ivan@a.com")
           (imp/derive-username "ivan@b.com")))))

(deftest escape-username-isolation-test
  ;; Row 10  quote-doubling is ONLY observable here (through derive it is nil).
  (testing "embedded double-quote is doubled in isolation (USR-02, defense-in-depth)"
    (is (= "a\"\"b"       (imp/escape-username "a\"b")))
    (is (= "\"\"\"\""     (imp/escape-username "\"\"")))
    (is (= "plain"        (imp/escape-username "plain")))))

(deftest execute-as-sql-test
  ;; Row 15  exact builder output — no trailing semicolon (spike-proven).
  (testing "builder emits the literal EXECUTE AS statement with no trailing ;"
    (is (= "EXECUTE AS \"test.user\" WITH NO REVERT"
           (imp/execute-as-sql "test.user"))))
  (testing "builder precondition forbids nil (never stringifies to \"null\")"
    (is (thrown? AssertionError (imp/execute-as-sql nil)))))

(deftest end-to-end-pipeline-test
  ;; Tracer invariant retained: a real email threads derive -> escape -> build.
  (is (= "EXECUTE AS \"test.user\" WITH NO REVERT"
         (imp/execute-as-sql (imp/derive-username "test.user@example.com")))))

;;; --------------------------------------------------------------------------
;;; EXECUTE AS error classifier (04-02, ERR-01 / ERR-02)
;;; The pure fn `execute-as-error->humanized` maps a raw StarRocks failure
;;; message -> {:type <qp-keyword> :message <string>} or nil. ERR-01 (privilege,
;;; live-verified §SC-4) is matched BEFORE ERR-02 (broad parse heuristic); an
;;; unrelated message returns nil so the caller rethrows generically (C-05).
;;; --------------------------------------------------------------------------

(def ^:private live-impersonate-msg
  ;; Live verbatim §SC-4 (01-FINDINGS.md) — the exact FE message a missing
  ;; IMPERSONATE privilege produces (SQLSTATE 42000).
  (str "(conn=33568104) Access denied; you need (at least one of) the "
       "IMPERSONATE privilege(s) on USER rls-test-2m for this operation."))

(deftest execute-as-error->humanized-err01-test
  (testing "live verbatim IMPERSONATE-privilege message -> ERR-01"
    (let [{:keys [type message]} (imp/execute-as-error->humanized live-impersonate-msg)]
      (is (= :qp/impersonation-privilege-missing type))
      ;; actionable: names the IMPERSONATE privilege and points at the GRANT recipe
      (is (re-find #"(?i)impersonate" message))
      (is (re-find #"(?i)grant impersonate" message))))
  (testing "case-varied `Impersonate Privilege` still classifies as ERR-01"
    (is (= :qp/impersonation-privilege-missing
           (:type (imp/execute-as-error->humanized
                   "Denied — missing Impersonate Privilege on USER bob."))))))

(deftest execute-as-error->humanized-err02-test
  (testing "syntax-error / Unexpected input parse signal -> ERR-02"
    (let [{:keys [type message]}
          (imp/execute-as-error->humanized
           "Getting syntax error from line 1. Unexpected input 'AS', the most similar input is {...}")]
      (is (= :qp/impersonation-unsupported-version type))
      (is (= "StarRocks 2.4+ is required for per-user impersonation (EXECUTE AS)." message))))
  (testing "each pre-2.4 parse variant classifies as ERR-02"
    (are [msg] (= :qp/impersonation-unsupported-version
                  (:type (imp/execute-as-error->humanized msg)))
      "Getting syntax error near 'EXECUTE'"
      "com.starrocks.sql.parser: no viable alternative at input 'AS'"
      "FE failed to parse the statement"
      "Unexpected input 'AS'")))

(deftest execute-as-error->humanized-ordering-test
  (testing "a message with BOTH privilege AND syntax phrases -> ERR-01 (most specific first)"
    (is (= :qp/impersonation-privilege-missing
           (:type (imp/execute-as-error->humanized
                   "syntax error; you need the IMPERSONATE privilege(s) on USER x"))))))

(deftest execute-as-error->humanized-unrelated-test
  (testing "unrelated failure -> nil (caller rethrows a generic loud ex-info)"
    (is (nil? (imp/execute-as-error->humanized "Table 'x' doesn't exist")))
    (is (nil? (imp/execute-as-error->humanized "Communications link failure")))))

;;; --------------------------------------------------------------------------
;;; 04-03 pure security-critical helpers (CR-01 / WR-03 / WR-05)
;;; impersonation-disposition — the fail-closed Seam-B decision core.
;;; normalize-user — case-fold + `<cluster>:` strip (relocated from starrocks.clj).
;;; identity-match? — case-insensitive identity comparison.
;;; All pure, total, JDBC-free — unit-tested under `:test` with no live StarRocks.
;;; --------------------------------------------------------------------------

(deftest impersonation-disposition-test
  (testing "toggle/flag matrix -> :impersonate / :pass-through / :indeterminate"
    (are [impersonating? arg out] (= out (imp/impersonation-disposition impersonating? arg))
      ;; flag off -> pass-through regardless of the argument shape
      false {:details {:enable-impersonation true}} :pass-through
      false 42                                      :pass-through
      false nil                                     :pass-through
      ;; flag on + readable toggle
      true  {:details {:enable-impersonation true}}   :impersonate
      true  {:details {:enable-impersonation "true"}} :impersonate
      true  {:details {:enable-impersonation false}}  :pass-through
      true  {:details {:enable-impersonation "false"}} :pass-through
      true  {:details {}}                             :pass-through
      ;; flag on but toggle is a truthy-but-NON-canonical value -> fail-closed
      ;; :indeterminate (CR-01 residual, C-05). EXACT boolean/"true"/"false"/nil
      ;; are the only legible forms; everything else refuses to guess.
      true  {:details {:enable-impersonation "1"}}     :indeterminate
      true  {:details {:enable-impersonation "TRUE"}}  :indeterminate
      true  {:details {:enable-impersonation "True"}}  :indeterminate
      true  {:details {:enable-impersonation 1}}       :indeterminate
      true  {:details {:enable-impersonation "on"}}    :indeterminate
      true  {:details {:enable-impersonation :true}}   :indeterminate
      ;; flag on but toggle UNREADABLE (arg not a map-with-:details) ->
      ;; fail-closed :indeterminate (CR-01)
      true  42                 :indeterminate
      true  {:no-details true} :indeterminate
      true  nil                :indeterminate)))

(deftest normalize-user-test
  (testing "reduce a StarRocks identity to a bare lowercase comparison key"
    (are [in out] (= out (imp/normalize-user in))
      "'alice'@'%'"                  "alice"
      "'default_cluster:alice'@'%'"  "alice"       ; strip <cluster>: qualifier (Pitfall 1)
      "'Alice'@'%'"                  "alice"        ; WR-03 case-fold
      "'DEFAULT_CLUSTER:Bob'@'%'"    "bob"          ; strip + fold together
      "  alice  "                    "alice"        ; trim
      "bob"                          "bob")))

(deftest identity-match?-test
  (testing "case-insensitive identity match (WR-03) still fail-closed on a real mismatch"
    ;; WR-03: a non-lowercase current_user() still matches the lowercase derived username
    (is (true?  (imp/identity-match? "alice" "'Alice'@'%'")))
    (is (true?  (imp/identity-match? "alice" "'alice'@'%'")))
    (is (true?  (imp/identity-match? "alice" "'default_cluster:alice'@'%'")))
    ;; genuine different user still fails closed
    (is (false? (imp/identity-match? "alice" "'bob'@'%'")))))
