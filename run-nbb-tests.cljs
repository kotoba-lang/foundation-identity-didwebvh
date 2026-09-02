(ns run-nbb-tests
  "The same conformance suite under ClojureScript, plus the async signing
   check.

   `.cljc` is a claim about two runtimes and the JVM suite only measures one.
   Both of the primitives this library leans on branch at the reader --
   `multiformats.core/sha256` and the Ed25519 arithmetic are different code
   paths here -- so the digests, the base58btc round trip and every
   signature are re-measured.

   The async check (`didwebvh.async-test/run`) is Promise-based rather than a
   `deftest`: cljs.test's `async` needs report plumbing this harness does not
   carry, and a run containing one returns nil -- the shape of \"nothing ran\".

   Exits 2 when nothing ran. A harness that reports success for zero tests is
   the failure this file exists to avoid: it looks exactly like a pass."
  (:require [clojure.test :as t]
            [didwebvh.async-test :as async-test]
            [didwebvh.conformance-test]))

(let [{:keys [fail error test]} (t/run-tests 'didwebvh.conformance-test)]
  (when (zero? test)
    (println "no tests ran -- refusing to report a pass")
    (js/process.exit 2))
  (println "async signing check (WebCrypto vs the pure signer)…")
  (-> (async-test/run)
      (.then (fn [async-failures]
               (println (str "async check: " async-failures " failed"))
               (js/process.exit (if (pos? (+ fail error async-failures)) 1 0))))))
