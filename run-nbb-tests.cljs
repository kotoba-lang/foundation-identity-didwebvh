(ns run-nbb-tests
  "The same conformance suite under ClojureScript.

   `.cljc` is a claim about two runtimes and the JVM suite only measures one.
   Both of the primitives this library leans on branch at the reader --
   `multiformats.core/sha256` is MessageDigest on the JVM and @noble/hashes in
   JS, `ed25519.core` is JCA and node:crypto -- so the digests, the base58btc
   round trip and every signature are DIFFERENT code paths here.

   Exits 2 when nothing ran. A harness that reports success for zero tests is
   the failure this file exists to avoid: it looks exactly like a pass."
  (:require [clojure.test :as t]
            [didwebvh.conformance-test]))

(let [{:keys [fail error test]} (t/run-tests 'didwebvh.conformance-test)]
  (when (zero? test)
    (println "no tests ran -- refusing to report a pass")
    (js/process.exit 2))
  (js/process.exit (if (pos? (+ fail error)) 1 0)))
