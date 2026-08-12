(ns metabase.driver.starrocks
  "StarRocks driver for Metabase.
   
   Extends the MySQL driver with StarRocks-specific functionality:
   - Fixes the SHOW GRANTS FOR CURRENT_USER incompatibility
   - Adds proper catalog support for multi-catalog environments
   - Handles StarRocks-specific metadata queries
   
   Based on Metabase's Starburst driver patterns for catalog handling."
  (:require
   [clojure.java.jdbc :as jdbc]
   [clojure.string :as str]
   [metabase.api.common :as api]
   [metabase.driver :as driver]
   [metabase.driver.sql-jdbc.connection :as sql-jdbc.conn]
   [metabase.driver.sql-jdbc.execute :as sql-jdbc.execute]
   [metabase.driver.sql-jdbc.sync :as sql-jdbc.sync]
   [metabase.driver.sql.query-processor :as sql.qp]
   [metabase.driver.starrocks.impersonation :as impersonation]
   [metabase.util.log :as log])
  (:import
   (java.sql Connection ResultSet ResultSetMetaData SQLException Statement)))

(set! *warn-on-reflection* true)

;; Register StarRocks as a driver that extends sql-jdbc (not mysql directly to avoid inheriting SHOW GRANTS behavior)
(driver/register! :starrocks :parent :sql-jdbc)

;;; +----------------------------------------------------------------------------------------------------------------+
;;; |                                          Driver Features                                                        |
;;; +----------------------------------------------------------------------------------------------------------------+

;; Declare what features StarRocks supports
(doseq [[feature supported?] {:set-timezone                    true
                              :basic-aggregations              true
                              :standard-deviation-aggregations true
                              :expressions                     true
                              :native-parameters               true
                              :expression-aggregations         true
                              :binning                         true
                              :foreign-keys                    false
                              :nested-field-columns            false
                              :connection/multiple-databases   true
                              :metadata/key-constraints        false
                              :now                             true
                              :datetime-diff                   true
                              :temporal-extract                true
                              :date-arithmetics                true
                              :advanced-math-expressions       true
                              :connection-impersonation        true}]   ; IMP-01 (D-01): native surface declared, kept dormant
  (defmethod driver/database-supports? [:starrocks feature] [_ _ _] supported?))

;;; +----------------------------------------------------------------------------------------------------------------+
;;; |                                          Connection Details                                                     |
;;; +----------------------------------------------------------------------------------------------------------------+

(defmethod sql-jdbc.conn/connection-details->spec :starrocks
  [_ {:keys [host port catalog dbname user password additional-options]
      :or   {host "localhost"
             port 9030
             catalog "default_catalog"}}]
  (let [;; Build the database name as catalog.database if both are provided
        ;; For external catalogs, StarRocks requires catalog.database format
        ;; If only catalog is provided, we use catalog.information_schema as a valid connection target
        ;; This allows us to connect and then query SHOW DATABASES to list all databases
        catalog-trimmed (when catalog (str/trim catalog))
        dbname-trimmed (when dbname (str/trim dbname))
        
        db-name (cond
                  ;; Both catalog and database provided
                  (and (not (str/blank? catalog-trimmed)) 
                       (not (str/blank? dbname-trimmed)))
                  (str catalog-trimmed "." dbname-trimmed)
                  
                  ;; Only catalog provided - use information_schema as connection target
                  ;; This is a system database that always exists in every catalog
                  (not (str/blank? catalog-trimmed))
                  (str catalog-trimmed ".information_schema")
                  
                  ;; Fallback to default_catalog
                  :else
                  "default_catalog.information_schema")
        
        ;; Base JDBC spec using MariaDB driver (MySQL compatible)
        base-spec {:classname   "org.mariadb.jdbc.Driver"
                   :subprotocol "mysql"
                   :subname     (str "//" host ":" port "/" db-name)
                   :user        user
                   :password    password
                   ;; StarRocks-specific settings
                   :tinyInt1isBit "false"
                   :yearIsDateType "false"
                   :serverTimezone "UTC"
                   :useSSL "false"
                   :allowPublicKeyRetrieval "true"
                   :zeroDateTimeBehavior "convertToNull"}]
    ;; Merge any additional options
    (if (and additional-options (not (str/blank? additional-options)))
      (merge base-spec
             (into {}
                   (for [pair (str/split additional-options #"&")
                         :when (not (str/blank? pair))]
                     (let [[k v] (str/split pair #"=" 2)]
                       [(keyword k) (or v "")]))))
      base-spec)))

;;; +----------------------------------------------------------------------------------------------------------------+
;;; |                    Per-User Impersonation — EXECUTE AS runtime path (Phase 4)                                   |
;;; +----------------------------------------------------------------------------------------------------------------+
;;;
;;; When the `enable-impersonation` toggle is ON for a StarRocks database, every
;;; user query runs under that user's OWN StarRocks identity via a two-seam
;;; connection-swap (RESEARCH.md § Recommended Architecture):
;;;
;;;   Seam A — `driver/execute-reducible-query :starrocks` binds a query-only
;;;   dynamic flag `*impersonating?*` and delegates to the `:sql-jdbc` parent.
;;;   Sync / describe-* / can-connect? never call `execute-reducible-query`, so
;;;   the flag is never set for them → IMP-04 holds structurally (C-01).
;;;
;;;   Seam B — `sql-jdbc.execute/do-with-connection-with-options :starrocks`,
;;;   when the flag is bound AND the toggle is truthy AND the acting user
;;;   resolves, opens a FRESH non-pooled connection, issues `EXECUTE AS "<user>"
;;;   WITH NO REVERT` as the literal first statement, asserts the identity, then
;;;   runs the query and closes the connection (C-03/C-05). Every other path
;;;   falls through to unmodified pooled `:sql-jdbc` behavior.
;;;
;;; DESIGN INVARIANTS (lifted from the Phase-1 spike ns / RESEARCH.md):
;;; - NEVER pooled: `jdbc/get-connection` on a plain spec, never c3p0.
;;; - EXECUTE AS is irreversible within a session; `.close()` is the only way to
;;;   end the WITH NO REVERT scope, so the connection is used ONCE then closed.
;;; - FAIL LOUDLY: the impersonated branch's only exits are success or a thrown
;;;   `ex-info` — it NEVER falls through to the base/service account (Pitfall 3).

(defn- query-rows
  "Run `sql` on an already-open `conn` and return a vector of row vectors (each a
   vector of column values, in column order). Type-hinted so
   `*warn-on-reflection*` stays clean."
  [^Connection conn sql]
  (with-open [^Statement stmt (.createStatement conn)]
    (let [^ResultSet rs         (.executeQuery stmt sql)
          ^ResultSetMetaData md (.getMetaData rs)
          n                     (.getColumnCount md)]
      (loop [rows []]
        (if (.next rs)
          (recur (conj rows (mapv (fn [i] (.getObject rs (int i)))
                                  (range 1 (inc n)))))
          rows)))))

(defn- current-user-of
  "Return the held-open connection's session identity, verbatim, via
   `SELECT current_user()` (e.g. \"'alice'@'%'\")."
  [^Connection conn]
  (-> (query-rows conn "SELECT current_user()") ffirst str))

(defn- assert-current-user!
  "Throw LOUDLY unless `conn`'s identity matches `expected` (IMP-05). Never
   returns a boolean-and-continue: an identity mismatch is a hard stop so the
   caller can never run a query as the wrong (or base) user. Returns the raw
   `current_user()` string on success."
  [^Connection conn expected]
  (let [raw (current-user-of conn)]
    ;; WR-03: case-insensitive comparison via the pure impersonation/identity-match?
    ;; so a non-lowercase current_user() is not spuriously rejected; a genuine
    ;; mismatch still hard-fails (fail-closed, IMP-05).
    (when-not (impersonation/identity-match? expected raw)
      (throw (ex-info "EXECUTE AS identity mismatch — refusing to continue"
                      {:type :qp/impersonation-identity-mismatch
                       :expected expected
                       :actual (impersonation/normalize-user raw)
                       :actual-raw raw})))
    raw))

(defn- open-impersonated!
  "Open a BRAND-NEW non-pooled physical connection from `spec` (built by
   `connection-details->spec`, D-06) and switch its identity with
   `EXECUTE AS \"<username>\" WITH NO REVERT` (built by the Phase-2
   `impersonation/execute-as-sql`, C-06) as the literal FIRST executed statement
   (IMP-02). Returns the still-open `^Connection` — the CALLER owns it and MUST
   `.close()` it (closing is the only way to end the WITH NO REVERT scope,
   IMP-03). On failure closes the half-open connection first, then throws a
   humanized `ex-info` — ERR-01 (missing IMPERSONATE privilege) or ERR-02
   (StarRocks < 2.4) via `impersonation/execute-as-error->humanized`, else a
   generic loud `ex-info`. It NEVER continues as the base account (C-05). The
   catch wraps ONLY the machine-generated `EXECUTE AS` statement; the user's own
   query runs later in `(f conn)`, outside this catch, so the broad ERR-02 parse
   match cannot swallow the user's own query errors (T-04-06)."
  ^Connection [spec username]
  (let [^Connection conn (jdbc/get-connection spec)]
    (try
      (with-open [^Statement stmt (.createStatement conn)]
        (.execute stmt (impersonation/execute-as-sql username)))
      conn
      (catch Throwable t
        ;; WR-04: guard the failure-path close so a throwing `.close` (e.g. an
        ;; already-broken socket — a plausible cause of the EXECUTE AS failure)
        ;; can never replace the humanized ERR-01/ERR-02 (or generic loud) ex-info
        ;; the operator needs.
        (try (.close conn) (catch Throwable _))
        (if-let [humanized (impersonation/execute-as-error->humanized (str (.getMessage t)))]
          (throw (ex-info (:message humanized) {:type (:type humanized)} t))
          (throw (ex-info (str "Impersonation setup failed for StarRocks user "
                               (pr-str username) ": " (.getMessage t))
                          {:type :qp/impersonation-setup-failed :username username}
                          t)))))))

;;; Seam A — query-only marker. Bound true ONLY inside a user query; sync /
;;; describe-* / can-connect? never traverse `execute-reducible-query`, so this
;;; stays false for them (C-01, IMP-04).
(def ^:private ^:dynamic *impersonating?*
  "True only during a user query on the query-execution thread. Bound by Seam A,
   read by Seam B on the same thread (synchronous same-thread acquisition)."
  false)

(defmethod driver/execute-reducible-query :starrocks
  [driver query context respond]
  (binding [*impersonating?* true]
    ((get-method driver/execute-reducible-query :sql-jdbc)
     driver query context respond)))

;;; Seam B — connection swap. Engages the fresh non-pooled impersonated
;;; connection ONLY when the query-only flag is bound AND the toggle is truthy.
;;; D-01: engages on ANY Metabase edition when the toggle is ON (the
;;; `enable-impersonation` toggle is the single source of truth, C-04); the
;;; native `:connection-impersonation` feature plays no role in this activation.
(defmethod sql-jdbc.execute/do-with-connection-with-options :starrocks
  [driver db-or-id-or-spec options f]
  (case (impersonation/impersonation-disposition *impersonating?* db-or-id-or-spec)
    ;; Impersonated path (C-05 engage-or-hard-fail): the ONLY exits from here are
    ;; success or a thrown ex-info — NEVER a fall-through to the base account.
    :impersonate
    (let [email    (:email @api/*current-user*)
          username (impersonation/derive-username email)]
      (when-not username
        ;; WR-01/USR-03: fail loud but PII-free — the acting-user email is NOT
        ;; placed in ex-data (Metabase logs QP ex-data server-side, and the
        ;; email adds no diagnostic value the humanized message does not). This
        ;; mirrors the adjacent :indeterminate throw's non-PII :arg-class choice.
        (throw (ex-info (str "Impersonation is enabled but your Metabase login does not map to a "
                             "StarRocks user — cannot determine your StarRocks identity.")
                        {:type :qp/impersonation-no-identity})))
      ;; WR-02: debug-level engagement probe carrying only the derived StarRocks
      ;; username (a non-PII identifier) — never the acting-user email.
      (log/debugf "[IMPERSONATION] engaging EXECUTE AS as StarRocks user %s" (pr-str username))
      ;; WR-01: establish the SSH tunnel the same way the connection-test path does
      ;; (`can-connect?`). The macro applies `metabase.util.ssh`'s tunnel — rewriting
      ;; host/port to the local tunnel endpoint (a no-op when `ssh-tunnel` is off) —
      ;; around `connection-details->spec`, and keeps the tunnel open for the whole
      ;; body. The fresh-non-pooled + EXECUTE-AS-first + single-query + explicit-close
      ;; invariants (IMP-02/IMP-03, C-03) are preserved because `open-impersonated!`
      ;; and the `with-open` are unchanged inside the wrapper.
      (sql-jdbc.conn/with-connection-spec-for-testing-connection [spec [driver (:details db-or-id-or-spec)]]
        (with-open [^Connection conn (open-impersonated! spec username)]
          (assert-current-user! conn username)                  ; IMP-05, before the query runs
          (sql-jdbc.execute/set-default-connection-options! driver db-or-id-or-spec conn options)
          (f conn))))

    ;; Fail-closed (CR-01, C-05): impersonation is REQUIRED for this query but the
    ;; toggle cannot be read to prove it is OFF (the arg is an id / a spec lacking
    ;; :details / nil). We must NOT delegate to the base pooled :sql-jdbc account —
    ;; that silent fall-through is the exact cross-user leak this guard prevents
    ;; (Pitfall 3). Hard-fail with a non-PII diagnostic (the arg class, never the
    ;; email).
    :indeterminate
    (throw (ex-info (str "Cannot determine impersonation state for this query — "
                         "refusing to run as the base StarRocks account.")
                    {:type     :qp/impersonation-indeterminate
                     :arg-class (some-> db-or-id-or-spec class .getName)}))

    ;; Pass-through (SC3/IMP-04): toggle-off or non-query paths delegate to the
    ;; unchanged pooled :sql-jdbc behavior, exactly as the pre-change else-path did.
    :pass-through
    ((get-method sql-jdbc.execute/do-with-connection-with-options :sql-jdbc)
     driver db-or-id-or-spec options f)))

;;; +----------------------------------------------------------------------------------------------------------------+
;;; |                                          Type Mappings                                                          |
;;; +----------------------------------------------------------------------------------------------------------------+

(def ^:private starrocks-type->base-type
  "Map of StarRocks types to Metabase base types."
  (sql-jdbc.sync/pattern-based-database-type->base-type
   [[#"(?i)^boolean$"                  :type/Boolean]
    [#"(?i)^tinyint$"                  :type/Integer]
    [#"(?i)^smallint$"                 :type/Integer]
    [#"(?i)^int$"                      :type/Integer]
    [#"(?i)^bigint$"                   :type/BigInteger]
    [#"(?i)^largeint$"                 :type/BigInteger]
    [#"(?i)^float$"                    :type/Float]
    [#"(?i)^double$"                   :type/Float]
    [#"(?i)^decimal.*"                 :type/Decimal]
    [#"(?i)^varchar.*"                 :type/Text]
    [#"(?i)^char.*"                    :type/Text]
    [#"(?i)^string$"                   :type/Text]
    [#"(?i)^text$"                     :type/Text]
    [#"(?i)^json$"                     :type/JSON]
    [#"(?i)^date$"                     :type/Date]
    [#"(?i)^datetime$"                 :type/DateTime]
    [#"(?i)^timestamp$"                :type/DateTime]
    [#"(?i)^array.*"                   :type/Array]
    [#"(?i)^map.*"                     :type/Dictionary]
    [#"(?i)^struct.*"                  :type/*]
    [#"(?i)^bitmap$"                   :type/*]
    [#"(?i)^hll$"                      :type/*]
    [#"(?i)^percentile$"               :type/*]
    [#".*"                             :type/*]]))

(defmethod sql-jdbc.sync/database-type->base-type :starrocks
  [_ field-type]
  (starrocks-type->base-type field-type))

;;; +----------------------------------------------------------------------------------------------------------------+
;;; |                                          Metadata / Sync                                                        |
;;; +----------------------------------------------------------------------------------------------------------------+

;; Schemas to exclude from sync
(def ^:private excluded-schemas
  #{"information_schema" "_statistics_" "INFORMATION_SCHEMA"})

;; CRITICAL: Override current-user-table-privileges to avoid SHOW GRANTS FOR CURRENT_USER
;; StarRocks doesn't support this MySQL syntax
(defmethod sql-jdbc.sync/current-user-table-privileges :starrocks
  [_driver _conn-spec & _options]
  ;; Return nil to skip privilege checking - StarRocks handles permissions differently
  nil)

(defn- describe-catalog-sql
  "The SHOW DATABASES statement that will list all schemas/databases for the current catalog."
  [_driver]
  "SHOW DATABASES")

(defn- describe-schema-sql
  "The SHOW TABLES statement that will list all tables for the given schema/database."
  [_driver schema]
  (str "SHOW TABLES FROM `" schema "`"))

(defn- describe-table-sql
  "The DESCRIBE statement that will list information about the given table."
  [_driver schema table]
  (str "DESCRIBE `" schema "`.`" table "`"))

(defn- get-schemas
  "Gets all schemas/databases in the current catalog."
  [driver ^Connection conn]
  (with-open [stmt (.createStatement conn)]
    (let [sql (describe-catalog-sql driver)
          rs  (.executeQuery stmt sql)]
      (loop [schemas []]
        (if (.next ^ResultSet rs)
          (let [schema-name (.getString ^ResultSet rs 1)]
            (recur (if (contains? excluded-schemas schema-name)
                     schemas
                     (conj schemas schema-name))))
          schemas)))))

(defn- get-tables-in-schema
  "Gets all tables in the given schema/database."
  [driver ^Connection conn schema]
  (try
    (with-open [stmt (.createStatement conn)]
      (let [sql (describe-schema-sql driver schema)
            rs  (.executeQuery stmt sql)]
        (loop [tables []]
          (if (.next ^ResultSet rs)
            (recur (conj tables {:name   (.getString ^ResultSet rs 1)
                                 :schema schema}))
            tables))))
    (catch Exception e
      (log/warnf "Could not get tables from schema %s: %s" schema (.getMessage e))
      [])))

(defmethod driver/describe-database :starrocks
  [driver database]
  (sql-jdbc.execute/do-with-connection-with-options
   driver
   database
   nil
   (fn [^Connection conn]
     (let [schemas (get-schemas driver conn)
           tables  (into #{}
                         (mapcat (fn [schema]
                                   (get-tables-in-schema driver conn schema)))
                         schemas)]
       {:tables tables}))))

(defmethod driver/describe-table :starrocks
  [driver database {schema :schema, table-name :name}]
  (sql-jdbc.execute/do-with-connection-with-options
   driver
   database
   nil
   (fn [^Connection conn]
     (with-open [stmt (.createStatement conn)]
       (let [sql (describe-table-sql driver schema table-name)
             rs  (.executeQuery stmt sql)]
         {:schema schema
          :name   table-name
          :fields (loop [fields []
                         idx 0]
                    (if (.next ^ResultSet rs)
                      (let [col-name (.getString ^ResultSet rs "Field")
                            col-type (.getString ^ResultSet rs "Type")]
                        (recur (conj fields {:name              col-name
                                             :database-type     col-type
                                             :base-type         (starrocks-type->base-type col-type)
                                             :database-position idx})
                               (inc idx)))
                      (set fields)))})))))

;;; StarRocks doesn't support foreign keys. This is already declared above via
;;; `:metadata/key-constraints false`, which is what Metabase gates FK metadata
;;; fetching on, so no `describe-fks` implementation is needed here.

;;; +----------------------------------------------------------------------------------------------------------------+
;;; |                                          Query Processing                                                       |
;;; +----------------------------------------------------------------------------------------------------------------+

;; Use MySQL-style quoting since StarRocks is MySQL-compatible
(defmethod sql.qp/quote-style :starrocks [_] :mysql)

;; Metabase 0.59+ adds ESCAPE '\' for literal LIKE patterns used by
;; :contains/:starts-with/:ends-with filters. StarRocks does not parse explicit
;; ESCAPE syntax here, while backslash escaping is already treated as built in.
(defmethod sql.qp/transform-literal-like-pattern-honeysql :starrocks
  [_driver like-rhs-honeysql]
  like-rhs-honeysql)

(prefer-method sql.qp/transform-literal-like-pattern-honeysql :starrocks :sql)

;; /api/dataset/native prettification corrupts MySQL-style backtick identifiers
;; for StarRocks, e.g. `silver`.`table`.`field` -> ` silver `.` table `.` field `.
(defmethod driver/prettify-native-form :starrocks
  [_driver native-form]
  native-form)

;; Date/time handling
(defmethod sql.qp/unix-timestamp->honeysql [:starrocks :seconds]
  [_ _ expr]
  [:from_unixtime expr])

(defmethod sql.qp/unix-timestamp->honeysql [:starrocks :milliseconds]
  [_ _ expr]
  [:from_unixtime [:/ expr 1000]])

(defmethod sql.qp/current-datetime-honeysql-form :starrocks
  [_]
  :%now)

(defmethod sql.qp/date [:starrocks :default] [_ _ expr] expr)

(defmethod sql.qp/date [:starrocks :minute]
  [_ _ expr]
  [:date_trunc "minute" expr])

(defmethod sql.qp/date [:starrocks :hour]
  [_ _ expr]
  [:date_trunc "hour" expr])

(defmethod sql.qp/date [:starrocks :day]
  [_ _ expr]
  [:date_trunc "day" expr])

(defmethod sql.qp/date [:starrocks :week]
  [_ _ expr]
  [:date_trunc "week" expr])

(defmethod sql.qp/date [:starrocks :month]
  [_ _ expr]
  [:date_trunc "month" expr])

(defmethod sql.qp/date [:starrocks :quarter]
  [_ _ expr]
  [:date_trunc "quarter" expr])

(defmethod sql.qp/date [:starrocks :year]
  [_ _ expr]
  [:date_trunc "year" expr])

(defmethod sql.qp/date [:starrocks :minute-of-hour] [_ _ expr] [:minute expr])
(defmethod sql.qp/date [:starrocks :hour-of-day]   [_ _ expr] [:hour expr])
(defmethod sql.qp/date [:starrocks :day-of-month]  [_ _ expr] [:day expr])
(defmethod sql.qp/date [:starrocks :month-of-year] [_ _ expr] [:month expr])
(defmethod sql.qp/date [:starrocks :year-of-era]   [_ _ expr] [:year expr])
(defmethod sql.qp/date [:starrocks :day-of-week]   [_ _ expr] [:dayofweek expr])
(defmethod sql.qp/date [:starrocks :week-of-year]  [_ _ expr] [:week expr])
(defmethod sql.qp/date [:starrocks :quarter-of-year] [_ _ expr] [:quarter expr])

(defmethod sql.qp/add-interval-honeysql-form :starrocks
  [_ hsql-form amount unit]
  [:date_add hsql-form [:interval amount (keyword (name unit))]])

(defmethod sql.qp/datetime-diff [:starrocks :year]
  [_ unit x y]
  [:timestampdiff [:raw (name unit)] x y])

(defmethod sql.qp/datetime-diff [:starrocks :month]
  [_ unit x y]
  [:timestampdiff [:raw (name unit)] x y])

(defmethod sql.qp/datetime-diff [:starrocks :day]
  [_ unit x y]
  [:datediff y x])

(defmethod sql.qp/datetime-diff [:starrocks :hour]
  [_ unit x y]
  [:timestampdiff [:raw (name unit)] x y])

(defmethod sql.qp/datetime-diff [:starrocks :minute]
  [_ unit x y]
  [:timestampdiff [:raw (name unit)] x y])

(defmethod sql.qp/datetime-diff [:starrocks :second]
  [_ unit x y]
  [:timestampdiff [:raw (name unit)] x y])

(defmethod sql.qp/cast-temporal-string [:starrocks :Coercion/ISO8601->DateTime]
  [_ _ expr]
  [:cast expr :datetime])

(defmethod sql.qp/cast-temporal-string [:starrocks :Coercion/ISO8601->Date]
  [_ _ expr]
  [:cast expr :date])

(defmethod sql.qp/cast-temporal-string [:starrocks :Coercion/YYYYMMDDHHMMSSString->Temporal]
  [_ _ expr]
  [:cast expr :datetime])

(defmethod sql.qp/cast-temporal-byte [:starrocks :Coercion/YYYYMMDDHHMMSSBytes->Temporal]
  [_ _ expr]
  [:cast expr :datetime])

;;; +----------------------------------------------------------------------------------------------------------------+
;;; |                                          Driver Metadata                                                        |
;;; +----------------------------------------------------------------------------------------------------------------+

(defmethod driver/display-name :starrocks [_]
  "StarRocks")

(defmethod driver/db-start-of-week :starrocks [_]
  :monday)

(defmethod driver/db-default-timezone :starrocks
  [driver database]
  (sql-jdbc.execute/do-with-connection-with-options
   driver
   database
   nil
   (fn [^Connection conn]
     (try
       (with-open [stmt (.createStatement conn)]
         (let [rs (.executeQuery stmt "SELECT @@system_time_zone")]
           (when (.next ^ResultSet rs)
             (.getString ^ResultSet rs 1))))
       (catch Exception _
         "UTC")))))

;;; +----------------------------------------------------------------------------------------------------------------+
;;; |                                          Connection Testing                                                     |
;;; +----------------------------------------------------------------------------------------------------------------+

(defmethod driver/can-connect? :starrocks
  [driver details]
  (try
    (sql-jdbc.conn/with-connection-spec-for-testing-connection [spec [driver details]]
      ;; Just try a simple query to verify connection
      (jdbc/query spec ["SELECT 1"])
      true)
    (catch Exception e
      (log/errorf "StarRocks connection failed: %s" (.getMessage e))
      false)))

(defmethod driver/humanize-connection-error-message :starrocks
  [_ message]
  ;; Ensure message is a string
  (let [msg (if (string? message) message (str message))]
    (cond
      (re-find #"(?i)communications link failure" msg)
      "Unable to connect to StarRocks. Please check that the host and port are correct."
      
      (re-find #"(?i)access denied" msg)
      "Access denied. Please check your username and password."
      
      (re-find #"(?i)unknown database" msg)
      "Database not found. Please check the catalog and database names."
      
      (re-find #"(?i)unknown catalog" msg)
      "Catalog not found. Please check the catalog name."
      
      :else
      msg)))