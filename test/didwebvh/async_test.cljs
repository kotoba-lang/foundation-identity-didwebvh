(ns didwebvh.async-test
  "The async signing path (`entry/sign-async`, `witness-proof-async`) against
   two oracles: the synchronous path with the same key, and WebCrypto.

   Node's `crypto.subtle` implements Ed25519, so the WebCrypto signer a
   Cloudflare Worker would use is exercised for real here — the same seed,
   imported as PKCS#8, signs the same hashData — and the proof it yields must
   be byte-for-byte the one the pure in-process signer yields (Ed25519 is
   deterministic, so equality is the whole test, not merely verifiability).

   Not a `deftest`: cljs.test's `async` needs the `:end-run-tests` report
   plumbing, which the nbb harness does not have (a run with an async test
   returns nil — exactly the shape of \"nothing ran\" the harness refuses).
   `run` returns a Promise of the failure count and the harness chains it
   after the synchronous suite. ClojureScript only, by construction."
  (:require [didwebvh.entry :as entry]
            [didwebvh.hash :as h]
            [didwebvh.log :as log]
            [didwebvh.signer :as signer]))

(def seed (vec (map #(bit-and (* 11 %) 0xff) (range 32))))
(def pkcs8-prefix [0x30 0x2e 0x02 0x01 0x00 0x30 0x05 0x06 0x03 0x2b 0x65 0x70 0x04 0x22 0x04 0x20])

(defn- webcrypto-signer
  "`{:multikey :sign-fn}` whose sign-fn is crypto.subtle.sign over a
   non-extractable key imported from the seed's PKCS#8 form."
  [multikey]
  (-> (js/crypto.subtle.importKey "pkcs8" (js/Uint8Array.from (clj->js (into pkcs8-prefix seed)))
                                  #js {:name "Ed25519"} false #js ["sign"])
      (.then (fn [key]
               {:multikey multikey
                :sign-fn (fn [hash-data]
                           (-> (js/crypto.subtle.sign "Ed25519" key (js/Uint8Array.from (clj->js hash-data)))
                               (.then #(js/Uint8Array. %))))}))))

(defn run
  "Promise of the number of failed checks (0 = pass). Prints each check."
  []
  (let [failures (atom 0)
        check! (fn [label ok? & [detail]]
                 (if ok? (println "ok  -" label)
                     (do (println "FAIL-" label (or detail "")) (swap! failures inc))))
        sync-signer (signer/from-seed seed)
        unsigned (entry/genesis {:version-time "2026-09-02T00:00:00Z"
                                 :parameters {"method" h/method-1-0
                                              "scid" h/scid-placeholder
                                              "updateKeys" [(:multikey sync-signer)]
                                              "portable" false}
                                 :state {"@context" ["https://www.w3.org/ns/did/v1"]
                                         "id" (str "did:webvh:" h/scid-placeholder ":async.example")}})
        expected (entry/sign unsigned sync-signer)]
    (-> (webcrypto-signer (:multikey sync-signer))
        (.then (fn [wc]
                 (-> (entry/sign-async unsigned wc)
                     (.then (fn [actual]
                              (check! "sign-async (WebCrypto) reproduces sign (pure) byte for byte"
                                      (= expected actual)
                                      (pr-str [(get-in expected ["proof" 0 "proofValue"])
                                               (get-in actual ["proof" 0 "proofValue"])]))
                              (check! "the resolver accepts the async-signed genesis"
                                      (:ok? (log/verify [actual] {:now 1800000000})))
                              (entry/witness-proof-async (get actual "versionId") wc)))
                     (.then (fn [wp]
                              (check! "witness-proof-async likewise"
                                      (= (entry/witness-proof (get expected "versionId") sync-signer) wp)))))))
        (.catch (fn [e] (check! "async signing threw" false (str e))))
        (.then (fn [] @failures)))))
