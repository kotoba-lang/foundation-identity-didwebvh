(ns didwebvh.conformance-test
  "Every negative here breaks exactly the thing it claims to break, and the
   positive alongside it is re-run unbroken. A test that reaches the right
   `:error` for the wrong reason -- a malformed document, a reader that threw
   -- is the failure mode this suite is written against."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [didwebvh.did :as did]
            [didwebvh.entry :as entry]
            [didwebvh.hash :as h]
            [didwebvh.log :as log]
            [didwebvh.signer :as signer]
            [didwebvh.time :as t]
            [didwebvh.witness :as witness]))

;; ── fixtures ─────────────────────────────────────────────────────────────────

(defn- seed [n] (byte-array (map unchecked-byte (repeat 32 n))))

(def update-1 (signer/from-seed (seed 1)))
(def update-2 (signer/from-seed (seed 2)))
(def update-3 (signer/from-seed (seed 3)))
(def attacker (signer/from-seed (seed 9)))

(def witnesses
  (mapv (fn [[role n]] (assoc (signer/from-seed (seed n)) :role role))
        [[:security 11] [:legal 12] [:operations 13] [:auditor 14] [:recovery 15]]))

(def witness-param
  {"threshold" 3
   "witnesses" (mapv (fn [w] {"id" (:did-key w)}) witnesses)})

(def t0 "2026-08-20T00:00:00Z")
(def t1 "2026-08-21T00:00:00Z")
(def now (+ (t/parse t1) 3600))

(def domain "did.example.com")

(defn- genesis-params [& {:keys [portable witness pre-rotate-to]
                          :or {portable true witness witness-param
                               pre-rotate-to update-2}}]
  (cond-> {"method" h/method-1-0
           "scid" h/scid-placeholder
           "updateKeys" [(:multikey update-1)]
           "portable" portable
           "witness" witness}
    pre-rotate-to (assoc "nextKeyHashes" [(h/key-hash (:multikey pre-rotate-to))])))

(defn- state-for [domain* path]
  {"@context" ["https://www.w3.org/ns/did/v1"]
   "id" (str "did:webvh:" h/scid-placeholder ":" domain*
             (when (seq path) (str ":" (str/join ":" path))))})

(defn- witness-file-for [version-id ws]
  [{"versionId" version-id
    "proof" (mapv #(entry/witness-proof version-id %) ws)}])

(defn- genesis-entry [& {:keys [params state] :or {params (genesis-params)
                                                   state (state-for domain nil)}}]
  (-> (entry/genesis {:version-time t0 :parameters params :state state})
      (entry/sign update-1)))

;; ── SCID and the DID string ──────────────────────────────────────────────────

(deftest scid-is-46-base58btc-characters
  (let [e (genesis-entry)
        scid (get-in e ["parameters" "scid"])]
    (is (= 46 (count scid)))
    (is (h/sha256-multihash? scid))
    (is (not (str/includes? (pr-str e) h/scid-placeholder))
        "no placeholder survives into the published entry")))

(deftest did-to-https-transformation
  (let [scid (get-in (genesis-entry) ["parameters" "scid"])]
    (testing "a bare domain publishes under .well-known"
      (is (= (str "https://" domain "/.well-known/did.jsonl")
             (did/log-url (str "did:webvh:" scid ":" domain))))
      (is (= (str "https://" domain "/.well-known/did-witness.json")
             (did/witness-url (str "did:webvh:" scid ":" domain)))))
    (testing "path segments become path segments"
      (is (= "https://identity.example.com/orgs/acme/did.jsonl"
             (did/log-url (str "did:webvh:" scid ":identity.example.com:orgs:acme")))))
    (testing "a port is %3A in the DID and a colon in the URL"
      (is (= "https://example.com:3000/path/did.jsonl"
             (did/log-url (str "did:webvh:" scid ":example.com%3A3000:path"))))
      (is (= (str "did:webvh:" scid ":example.com%3A3000:path")
             (did/build {:scid scid :domain "example.com" :port 3000 :path ["path"]}))))
    (testing "what it refuses"
      (is (thrown? Exception (did/parse (str "did:webvh:" scid ":192.0.2.1"))))
      (is (thrown? Exception (did/parse (str "did:webvh:" scid ":example.com:..")))))))

;; ── the happy path ───────────────────────────────────────────────────────────

(deftest genesis-with-three-of-five-witnesses-verifies
  (let [e (genesis-entry)
        v (get e "versionId")
        result (log/verify [e] {:witness-file (witness-file-for v (take 3 witnesses))
                                :now now})]
    (is (:ok? result) (pr-str (dissoc result :versions)))
    (is (= 3 (get-in result [:versions 0 :witness :weight])))
    (is (true? (:portable? result)))
    (is (false? (:deactivated? result)))
    (is (true? (:checked-future-dating? result)))
    (is (= [(:multikey update-1)] (get-in result [:versions 0 :signed-by])))))

;; ── the threshold is a method rule, not a promise ────────────────────────────

(deftest two-of-five-is-refused
  (let [e (genesis-entry)
        v (get e "versionId")
        two (log/verify [e] {:witness-file (witness-file-for v (take 2 witnesses)) :now now})
        three (log/verify [e] {:witness-file (witness-file-for v (take 3 witnesses)) :now now})]
    (is (= :didwebvh/witness-threshold-unmet (:error two)))
    (is (= 2 (get-in two [:witness :weight])))
    (is (:ok? three) "the same entry with one more witness passes")))

(deftest a-witness-file-that-is-absent-is-not-an-approval
  (let [e (genesis-entry)]
    (is (= :didwebvh/witness-threshold-unmet
           (:error (log/verify [e] {:now now})))
        "no file must fail the threshold, not skip the check")))

(deftest a-proof-from-a-key-that-is-not-a-witness-does-not-count
  (let [e (genesis-entry)
        v (get e "versionId")
        forged (witness-file-for v [(first witnesses) (second witnesses) attacker])
        genuine (witness-file-for v (take 3 witnesses))]
    (is (= :didwebvh/witness-threshold-unmet (:error (log/verify [e] {:witness-file forged :now now}))))
    (is (:ok? (log/verify [e] {:witness-file genuine :now now})))))

(deftest one-witness-signing-twice-is-still-one-witness
  (let [e (genesis-entry)
        v (get e "versionId")
        doubled [{"versionId" v
                  "proof" [(entry/witness-proof v (first witnesses))
                           (entry/witness-proof v (assoc (first witnesses) :created t1))
                           (entry/witness-proof v (second witnesses))]}]]
    (is (= :didwebvh/witness-threshold-unmet
           (:error (log/verify [e] {:witness-file doubled :now now})))
        "three proofs, two witnesses, threshold three")))

(deftest a-witness-proof-cannot-be-replayed-onto-another-version
  (let [e (genesis-entry)
        v (get e "versionId")
        other-version (str "2-" (h/hash-json {"x" 1}))
        replayed [{"versionId" v
                   "proof" (mapv #(entry/witness-proof other-version %) (take 3 witnesses))}]]
    (is (= :didwebvh/witness-threshold-unmet
           (:error (log/verify [e] {:witness-file replayed :now now}))))))

;; ── updateKeys alone is NOT m-of-n, and the library says so ──────────────────

(deftest any-single-update-key-signs-a-valid-entry
  (let [params (assoc (genesis-params :pre-rotate-to nil)
                      "updateKeys" [(:multikey update-1) (:multikey update-2)])
        signed-by-second (-> (entry/genesis {:version-time t0 :parameters params
                                             :state (state-for domain nil)})
                             (entry/sign update-2))
        v (get signed-by-second "versionId")]
    (is (:ok? (log/verify [signed-by-second]
                          {:witness-file (witness-file-for v (take 3 witnesses)) :now now}))
        "two updateKeys and one signature is a valid entry -- the reason the witness threshold exists")))

;; ── pre-rotation ─────────────────────────────────────────────────────────────

(defn- update-entry [previous signer* & {:keys [next-key state]
                                         :or {next-key update-3}}]
  (-> (entry/next-entry previous
                        {:version-time t1
                         :parameters {"updateKeys" [(:multikey signer*)]
                                      "nextKeyHashes" [(h/key-hash (:multikey next-key))]}
                         :state (or state (get previous "state"))})
      (entry/sign signer*)))

(deftest a-pre-committed-key-may-rotate-in
  (let [e1 (genesis-entry)
        e2 (update-entry e1 update-2)
        wf (into (witness-file-for (get e1 "versionId") (take 3 witnesses))
                 (witness-file-for (get e2 "versionId") (take 3 witnesses)))
        result (log/verify [e1 e2] {:witness-file wf :now now})]
    (is (:ok? result) (pr-str (dissoc result :versions)))
    (is (= 2 (count (:versions result))))))

(deftest a-key-nobody-pre-committed-cannot-rotate-in
  (let [e1 (genesis-entry)
        stolen (update-entry e1 attacker)
        honest (update-entry e1 update-2)
        wf-for (fn [e] (into (witness-file-for (get e1 "versionId") (take 3 witnesses))
                             (witness-file-for (get e "versionId") (take 3 witnesses))))]
    (is (= :didwebvh/uncommitted-update-key
           (:error (log/verify [e1 stolen] {:witness-file (wf-for stolen) :now now})))
        "the current update key was compromised and still cannot name its own successor")
    (is (:ok? (log/verify [e1 honest] {:witness-file (wf-for honest) :now now})))))

(deftest pre-rotation-forbids-inheriting-update-keys
  (let [e1 (genesis-entry)
        lazy (-> (entry/next-entry e1 {:version-time t1
                                       :parameters {}
                                       :state (get e1 "state")})
                 (entry/sign update-2))
        wf (into (witness-file-for (get e1 "versionId") (take 3 witnesses))
                 (witness-file-for (get lazy "versionId") (take 3 witnesses)))]
    (is (= :didwebvh/pre-rotation-inheritance
           (:error (log/verify [e1 lazy] {:witness-file wf :now now}))))))

;; ── portability ──────────────────────────────────────────────────────────────

(deftest a-portable-did-may-move-and-keeps-its-scid
  (let [e1 (genesis-entry)
        scid (get-in e1 ["parameters" "scid"])
        moved-id (str "did:webvh:" scid ":did.new-example.com")
        e2 (update-entry e1 update-2
                         :state {"@context" ["https://www.w3.org/ns/did/v1"]
                                 "id" moved-id
                                 "alsoKnownAs" [(get-in e1 ["state" "id"])]})
        wf (into (witness-file-for (get e1 "versionId") (take 3 witnesses))
                 (witness-file-for (get e2 "versionId") (take 3 witnesses)))
        result (log/verify [e1 e2] {:witness-file wf :now now :expect-did moved-id})]
    (is (:ok? result) (pr-str (dissoc result :versions)))
    (is (= moved-id (:did result)))
    (is (= scid (:scid result)) "the SCID survives the move -- that is what portability means")
    (is (= "https://did.new-example.com/.well-known/did.jsonl" (:log-url result)))))

(deftest a-non-portable-did-may-not-move
  (let [e1 (genesis-entry :params (genesis-params :portable false))
        scid (get-in e1 ["parameters" "scid"])
        e2 (update-entry e1 update-2
                         :state {"@context" ["https://www.w3.org/ns/did/v1"]
                                 "id" (str "did:webvh:" scid ":did.new-example.com")})
        stay (update-entry e1 update-2)
        wf-for (fn [e] (into (witness-file-for (get e1 "versionId") (take 3 witnesses))
                             (witness-file-for (get e "versionId") (take 3 witnesses))))]
    (is (= :didwebvh/not-portable (:error (log/verify [e1 e2] {:witness-file (wf-for e2) :now now}))))
    (is (:ok? (log/verify [e1 stay] {:witness-file (wf-for stay) :now now})))))

(deftest portability-cannot-be-switched-on-later
  (let [e1 (genesis-entry :params (genesis-params :portable false))
        e2 (-> (entry/next-entry e1 {:version-time t1
                                     :parameters {"updateKeys" [(:multikey update-2)]
                                                  "nextKeyHashes" [(h/key-hash (:multikey update-3))]
                                                  "portable" true}
                                     :state (get e1 "state")})
               (entry/sign update-2))
        wf (into (witness-file-for (get e1 "versionId") (take 3 witnesses))
                 (witness-file-for (get e2 "versionId") (take 3 witnesses)))]
    (is (= :didwebvh/portable-enabled-late
           (:error (log/verify [e1 e2] {:witness-file wf :now now}))))))

;; ── tampering ────────────────────────────────────────────────────────────────

(deftest an-edited-state-breaks-the-entry-hash
  (let [e (genesis-entry)
        v (get e "versionId")
        tampered (assoc-in e ["state" "service"] [{"id" "#x" "type" "Evil"}])
        wf (witness-file-for v (take 3 witnesses))]
    (is (= :didwebvh/entry-hash-mismatch (:error (log/verify [tampered] {:witness-file wf :now now}))))
    (is (:ok? (log/verify [e] {:witness-file wf :now now})))))

(deftest an-entry-signed-by-a-key-outside-updateKeys-is-refused
  (let [params (genesis-params)
        forged (-> (entry/genesis {:version-time t0 :parameters params
                                   :state (state-for domain nil)})
                   (entry/sign attacker))
        v (get forged "versionId")
        wf (witness-file-for v (take 3 witnesses))]
    (is (= :didwebvh/unauthorized-entry (:error (log/verify [forged] {:witness-file wf :now now}))))))

(deftest a-log-that-skips-a-version-is-refused
  (let [e1 (genesis-entry)
        e2 (update-entry e1 update-2)
        wf (into (witness-file-for (get e1 "versionId") (take 3 witnesses))
                 (witness-file-for (get e2 "versionId") (take 3 witnesses)))]
    (is (= :didwebvh/bad-version-number (:error (log/verify [e2] {:witness-file wf :now now})))
        "entry 2 presented as the whole log is not entry 1")))

(deftest version-time-must-move-forward
  (let [e1 (genesis-entry)
        backwards (-> (entry/next-entry e1 {:version-time t0
                                            :parameters {"updateKeys" [(:multikey update-2)]
                                                         "nextKeyHashes" [(h/key-hash (:multikey update-3))]}
                                            :state (get e1 "state")})
                      (entry/sign update-2))
        wf (into (witness-file-for (get e1 "versionId") (take 3 witnesses))
                 (witness-file-for (get backwards "versionId") (take 3 witnesses)))]
    (is (= :didwebvh/non-monotonic-version-time
           (:error (log/verify [e1 backwards] {:witness-file wf :now now}))))))

(deftest a-future-dated-entry-is-refused-only-when-now-is-known
  (let [e (genesis-entry)
        v (get e "versionId")
        wf (witness-file-for v (take 3 witnesses))
        long-ago (- (t/parse t0) 86400)
        without-now (log/verify [e] {:witness-file wf})]
    (is (= :didwebvh/future-version-time (:error (log/verify [e] {:witness-file wf :now long-ago}))))
    (is (:ok? without-now))
    (is (false? (:checked-future-dating? without-now))
        "a check that could not run must say it did not run")))

;; ── units ────────────────────────────────────────────────────────────────────

(deftest key-hash-is-over-the-multikey-string
  (is (= (h/digest (h/utf8 (:multikey update-2)))
         (h/key-hash (:multikey update-2)))))

(deftest witness-validation-refuses-an-unreachable-threshold
  (is (thrown? Exception
               (witness/validate! {"threshold" 6 "witnesses" (get witness-param "witnesses")})))
  (is (nil? (witness/validate! witness-param)))
  (is (nil? (witness/validate! {})) "declaring no witnesses is legal"))

(deftest version-time-round-trips
  (is (= t0 (t/->iso8601 (t/parse t0))))
  (is (= (t/parse "2026-08-20T00:00:00Z") (t/parse "2026-08-20T00:00:00.500Z")))
  (is (nil? (t/parse "2026-08-20T00:00:00+09:00")) "the method requires UTC"))
