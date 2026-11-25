(herald "AP2 with status check (Sigma_AP2^+): security goals, agent key not assumed secret")
;; Generated for the AP2 formal-methods section. CPSA 4.4.9.
;; One of three models, one per strand space: ap2_goals.scm (Sigma_AP2),
;; ap2_fanout_goals.scm (Sigma_AP2^F) and fanoutFix_goals.scm (Sigma_AP2^+).

;; (privk agent) is not assumed non-originating. The status query and its answer
;; travel over HTTPS (see the comment in defprotocol).

;;Compressed macros used to make roles less cluttered
(defmacro (ocmOf item merchant user agent)
  (openCheckoutMandate item merchant user agent))

(defmacro (opmOf total item merchant user agent)
  (openPaymentMandate total (hash (ocmOf item merchant user agent)) user agent))

(defmacro (cpmOf n total item merchant o user agent)
  (closedPaymentMandate n total (hash (checkoutJwt item merchant o))
    (opmOf total item merchant user agent) agent))

(defmacro (ccmOf n item merchant o user agent)
  (closedCheckoutMandate n (checkoutJwt item merchant o)
    (ocmOf item merchant user agent) agent))

(defmacro (checkoutJwt item merchant orderId)
  (cat item merchant orderId
       (enc (hash item merchant orderId) (privk merchant))))

;;Regular Mandate Macros
(defmacro (openCheckoutMandate item merchant tsKey agentKey)
  (cat "open" "checkout" item merchant (pubk agentKey)
       (enc (hash "open" "checkout" item merchant (pubk agentKey)) (privk tsKey))))

(defmacro (closedCheckoutMandate nonce checkoutJwt openMandate agentKey)
  (cat "closed" "checkout" nonce checkoutJwt
       (enc (hash "closed" "checkout" nonce (hash checkoutJwt) (hash openMandate)) (privk agentKey))))

(defmacro (openPaymentMandate total checkoutMandate tsKey agentKey)
  (cat "open" "payment" total checkoutMandate (pubk agentKey)
       (enc (hash "open" "payment" checkoutMandate total (pubk agentKey)) (privk tsKey))))

;;txId = transaction identifier, which an honest agent sets to the hash of the checkout JWT
;; We have to model it this way because the cp should not see the actual checkoutJwt
(defmacro (closedPaymentMandate nonce total  txId openMandate agentKey)
  (cat "closed" "payment" nonce  total txId (hash openMandate)
       (enc (hash "closed" "payment" nonce total txId (hash openMandate)) (privk agentKey))))

;;cpm = closedPaymentMandate
;;cp = Credential Provider name
(defmacro (paymentToken token cpm cp)
  (cat token (enc (hash "token" token (hash cpm)) (privk cp))))

;;Receipt a CP returns when the TS reports the open mandate revoked
(defmacro (rejectionReceipt cpm cp)
  (cat "rejected" (hash cpm) (enc (hash "rejected" (hash cpm)) (privk cp))))

(defprotocol ap2 basic
    ;;The TS stands in for the user.
    ;; The CP and the TS exchange each status query and its answer over HTTPS, that is,
    ;; TLS with only the server authenticated. Each connection is a channel. The CP roles
    ;; assume their channel is authenticated and confidential, because a CP validates the
    ;; TS's certificate. The TS role assumes nothing, because the TS does not authenticate
    ;; its clients: the adversary can query it over a connection of its own.

    (defrole TS
        (vars (user agent merchant name) (item total data) (nc1 nc2 text) (ch1 ch2 chan))
        (trace
               (recv  (cat item merchant total (pubk agent)))
               (send (cat
                        (openCheckoutMandate item merchant user agent)
                        (openPaymentMandate total
                            (hash (openCheckoutMandate item merchant user agent))  user agent)))
               ;; First status check: the open mandate is unused, so it is valid
               (recv ch1 (cat "status" (opmOf total item merchant user agent) nc1))
               (send ch1 (cat "valid" (hash (opmOf total item merchant user agent)) nc1))
               ;; Second status check: the open mandate has been used, so it is revoked
               (recv ch2 (cat "status" (opmOf total item merchant user agent) nc2))
               (send ch2 (cat "revoked" (hash (opmOf total item merchant user agent)) nc2))
               ))

    (defrole agent
        (vars (user agent merchant cp name) (item total token data) (orderId n1 text))
        (trace
               (send  (cat item merchant total (pubk agent)))
               (recv (cat
                        (openCheckoutMandate item merchant user agent)
                        (openPaymentMandate total
                            (hash (openCheckoutMandate item merchant user agent))  user agent)))
                (send (cat "cart" item))
                (recv (checkoutJwt item merchant orderId))
                (send (cat (openPaymentMandate total
                            (hash (openCheckoutMandate item merchant user agent))  user agent)
                        (closedPaymentMandate n1 total (hash (checkoutJwt item merchant orderId))
                            (openPaymentMandate total
                                (hash (openCheckoutMandate item merchant user agent))  user agent)
                            agent)))
                (recv (paymentToken token
                        (closedPaymentMandate n1 total (hash (checkoutJwt item merchant orderId))
                            (openPaymentMandate total
                                (hash (openCheckoutMandate item merchant user agent))  user agent)
                            agent)
                        cp)) ;; send The payment token, closed payment mandate, and credential provider name
                (send (cat
                        (openCheckoutMandate item merchant user agent)
                        (closedCheckoutMandate n1
                           (checkoutJwt item merchant orderId)
                           (openCheckoutMandate item merchant user agent)
                           agent)
                          (paymentToken token
                            (closedPaymentMandate n1 total (hash (checkoutJwt item merchant orderId))
                                (openPaymentMandate total
                                    (hash (openCheckoutMandate item merchant user agent))  user agent)
                                agent)
                            cp)  )
                  )
                )
        (uniq-orig n1)
        )

    (defrole merchant
        (vars (user agent merchant cp name) (item total token data) (orderId n1 text))
        (trace
            (recv (cat "cart" item))
            (send (checkoutJwt item merchant orderId))
            (recv (cat
                (openCheckoutMandate item merchant user agent)
                (closedCheckoutMandate n1
                   (checkoutJwt item merchant orderId)
                   (openCheckoutMandate item merchant user agent)
                   agent)
              (paymentToken token
                (closedPaymentMandate n1 total (hash (checkoutJwt item merchant orderId))
                    (openPaymentMandate total
                        (hash (openCheckoutMandate item merchant user agent))  user agent)
                    agent)
                cp))
              )
            )
        (uniq-orig orderId)
    )


    (defrole CP
      (vars (user agent cp name) (total token data) (n1 nc text) (txId ocm mesg) (ch chan))
      (trace
        (recv (cat (openPaymentMandate total ocm user agent)
                   (closedPaymentMandate n1 total txId
                     (openPaymentMandate total ocm user agent) agent)))
        ;; Status check over HTTPS: a copy of the open mandate plus a fresh nonce
        (send ch (cat "status" (openPaymentMandate total ocm user agent) nc))
        ;; TS answers valid on the same connection, echoing the nonce
        (recv ch (cat "valid" (hash (openPaymentMandate total ocm user agent)) nc))
        (send (paymentToken token
                (closedPaymentMandate n1 total txId
                  (openPaymentMandate total ocm user agent) agent)
                cp)))
      (uniq-orig token nc)
      (auth ch)
      (conf ch))

    ;; Same check, but the TS answers revoked, so the CP returns a receipt instead of a token
    (defrole CPreject
      (vars (user agent cp name) (total data) (n1 nc text) (txId ocm mesg) (ch chan))
      (trace
        (recv (cat (openPaymentMandate total ocm user agent)
                   (closedPaymentMandate n1 total txId
                     (openPaymentMandate total ocm user agent) agent)))
        (send ch (cat "status" (openPaymentMandate total ocm user agent) nc))
        (recv ch (cat "revoked" (hash (openPaymentMandate total ocm user agent)) nc))
        (send (rejectionReceipt
                (closedPaymentMandate n1 total txId
                  (openPaymentMandate total ocm user agent) agent)
                cp)))
      (uniq-orig nc)
      (auth ch)
      (conf ch))



(defrole fanout
  (vars (user agent merchant cp1 cp2 name) (item total t1 t2 data) (o1 o2 n1 n2 text))
  (trace
    ;; one authorization from the TS
    (send (cat item merchant total (pubk agent)))
    (recv (cat (ocmOf item merchant user agent)
               (opmOf total item merchant user agent)))
    ;; purchase 1: closed mandates under n1, paid through cp1
    (send (cat "cart" item))
    (recv (checkoutJwt item merchant o1))
    (send (cat (opmOf total item merchant user agent)
               (cpmOf n1 total item merchant o1 user agent)))
    (recv (paymentToken t1 (cpmOf n1 total item merchant o1 user agent) cp1))
    (send (cat (ocmOf item merchant user agent)
               (ccmOf n1 item merchant o1 user agent)
               (paymentToken t1 (cpmOf n1 total item merchant o1 user agent) cp1)))
    ;; purchase 2: same open mandates, fresh n2, paid through cp2
    (send (cat "cart" item))
    (recv (checkoutJwt item merchant o2))
    (send (cat (opmOf total item merchant user agent)
               (cpmOf n2 total item merchant o2 user agent)))
    (recv (paymentToken t2 (cpmOf n2 total item merchant o2 user agent) cp2))
    (send (cat (ocmOf item merchant user agent)
               (ccmOf n2 item merchant o2 user agent)
               (paymentToken t2 (cpmOf n2 total item merchant o2 user agent) cp2))))
  (uniq-orig n1 n2))

  ;; The TS is one sequential process per user: its trace stands in for its state,
  ;; so it can answer valid only once.
  (defrule one-ts-per-user
    (forall ((z1 z2 strd) (u name))
      (implies
        (and (p "TS" z1 1) (p "TS" z2 1)
             (p "TS" "user" z1 u) (p "TS" "user" z2 u))
        (= z1 z2)))
    (comment "Any two TS strands for the same user are the same strand"))
)



;; SG1-M and SG2, merchant view, orig_M = Non(sk U), Non(sk M), Non(sk C), Uniq(o).
;; No assumption on (privk agent).
(defgoal ap2
  (forall ((z strd) (user agent merchant cp name) (item total token data) (orderId n1 text))
    (implies
      (and (p "merchant" z 3)
           (p "merchant" "user" z user) (p "merchant" "agent" z agent)
           (p "merchant" "merchant" z merchant) (p "merchant" "cp" z cp)
           (p "merchant" "item" z item) (p "merchant" "total" z total)
           (p "merchant" "token" z token) (p "merchant" "orderId" z orderId)
           (p "merchant" "n1" z n1)
           (non (privk user)) (non (privk merchant)) (non (privk cp))
           (uniq-at orderId z 1))
      (exists ((z-0 z-1 strd))
        (and (p "TS" z-0 2)
             (p "TS" "user" z-0 user) (p "TS" "agent" z-0 agent)
             (p "TS" "merchant" z-0 merchant) (p "TS" "item" z-0 item)
             (p "TS" "total" z-0 total)
             (p "CP" z-1 4)
             (p "CP" "user" z-1 user) (p "CP" "agent" z-1 agent) (p "CP" "cp" z-1 cp)
             (p "CP" "total" z-1 total) (p "CP" "n1" z-1 n1) (p "CP" "token" z-1 token)
             (p "CP" "txId" z-1 (hash item merchant orderId (enc (hash item merchant orderId) (privk merchant))))
             (p "CP" "ocm" z-1 (hash "open" "checkout" item merchant (pubk agent) (enc (hash "open" "checkout" item merchant (pubk agent)) (privk user))))))))
  (comment "SG1-M and SG2"))

;; Lemma (a), status authenticity, valid: a CP+ strand that received valid (k_acc = 3)
;; got it from the TS+ answer to its own query. Also gives SG1-C in Sigma_AP2^+.
;; orig_S = Non(sk U), Uniq(nc), Auth(c), Conf(c).
(defgoal ap2
  (forall ((z strd) (user agent name) (total data) (nc text) (ocm mesg) (ch chan))
    (implies
      (and (p "CP" z 3)
           (p "CP" "user" z user) (p "CP" "agent" z agent) (p "CP" "total" z total)
           (p "CP" "ocm" z ocm) (p "CP" "nc" z nc) (p "CP" "ch" z ch)
           (non (privk user)) (uniq-at nc z 1) (auth ch) (conf ch))
      (exists ((z-0 strd) (item data) (merchant name))
        (and (p "TS" z-0 4)
             (p "TS" "user" z-0 user) (p "TS" "agent" z-0 agent) (p "TS" "total" z-0 total)
             (p "TS" "item" z-0 item) (p "TS" "merchant" z-0 merchant)
             (p "TS" "nc1" z-0 nc) (p "TS" "ch1" z-0 ch)
             (= ocm (hash "open" "checkout" item merchant (pubk agent) (enc (hash "open" "checkout" item merchant (pubk agent)) (privk user))))
             (prec z 1 z-0 2) (prec z-0 3 z 2)))))
  (comment "Lemma (a) and SG1-C"))

;; Lemma (b), status authenticity, revoked: a CP- strand that received revoked
;; got it from the TS+ answer to its own query. orig_S.
(defgoal ap2
  (forall ((z strd) (user agent name) (total data) (nc text) (ocm mesg) (ch chan))
    (implies
      (and (p "CPreject" z 3)
           (p "CPreject" "user" z user) (p "CPreject" "agent" z agent)
           (p "CPreject" "total" z total)
           (p "CPreject" "ocm" z ocm) (p "CPreject" "nc" z nc) (p "CPreject" "ch" z ch)
           (non (privk user)) (uniq-at nc z 1) (auth ch) (conf ch))
      (exists ((z-0 strd) (item data) (merchant name))
        (and (p "TS" z-0 6)
             (p "TS" "user" z-0 user) (p "TS" "agent" z-0 agent) (p "TS" "total" z-0 total)
             (p "TS" "item" z-0 item) (p "TS" "merchant" z-0 merchant)
             (p "TS" "nc2" z-0 nc) (p "TS" "ch2" z-0 ch)
             (= ocm (hash "open" "checkout" item merchant (pubk agent) (enc (hash "open" "checkout" item merchant (pubk agent)) (privk user))))
             (prec z 1 z-0 4) (prec z-0 5 z 2)))))
  (comment "Lemma (b)"))

;; SG3-U, single use: two CP+ strands that received valid (k_acc = 3) for the same
;; (U, A, total, y) are one strand. orig_S for both strands.
(defgoal ap2
  (forall ((z1 z2 strd) (user agent name) (total data) (nc1 nc2 text) (ocm mesg) (ch1 ch2 chan))
    (implies
      (and (p "CP" z1 3) (p "CP" z2 3)
           (p "CP" "user" z1 user) (p "CP" "user" z2 user)
           (p "CP" "agent" z1 agent) (p "CP" "agent" z2 agent)
           (p "CP" "total" z1 total) (p "CP" "total" z2 total)
           (p "CP" "ocm" z1 ocm) (p "CP" "ocm" z2 ocm)
           (p "CP" "nc" z1 nc1) (p "CP" "nc" z2 nc2)
           (p "CP" "ch" z1 ch1) (p "CP" "ch" z2 ch2)
           (non (privk user))
           (uniq-at nc1 z1 1) (uniq-at nc2 z2 1) (auth ch1) (auth ch2) (conf ch1) (conf ch2))
      (= z1 z2)))
  (comment "SG3-U"))

;; SG3-R, revocation: no CP+ strand receives valid for a status query that follows the
;; TS+ revoked answer for the same open payment mandate. orig_S.
;; The paper states the precedence as (s,6) before (r,2), the CP's query node. CPSA orders
;; only transmissions before receptions, so the point of view orders (s,6) before (r,1);
;; the two are equivalent because (r,1) is the only reception node of r before (r,2).
(defgoal ap2
  (forall ((z z-0 strd) (user agent merchant name) (item total data) (nc text) (ch chan))
    (implies
      (and (p "CP" z 3)
           (p "CP" "user" z user) (p "CP" "agent" z agent) (p "CP" "total" z total)
           (p "CP" "ocm" z (hash "open" "checkout" item merchant (pubk agent) (enc (hash "open" "checkout" item merchant (pubk agent)) (privk user))))
           (p "CP" "nc" z nc) (p "CP" "ch" z ch)
           (p "TS" z-0 6)
           (p "TS" "user" z-0 user) (p "TS" "agent" z-0 agent) (p "TS" "total" z-0 total)
           (p "TS" "item" z-0 item) (p "TS" "merchant" z-0 merchant)
           (prec z-0 5 z 0)
           (non (privk user)) (uniq-at nc z 1) (auth ch) (conf ch))
      (false)))
  (comment "SG3-R"))

;; Non-vacuity of SG3-R: its hypothesis without the precedence has a shape, and in it
;; the TS+ strand answered this CP+ strand's query with its first, valid answer.
(defgoal ap2
  (forall ((z z-0 strd) (user agent merchant name) (item total data) (nc text) (ch chan))
    (implies
      (and (p "CP" z 3)
           (p "CP" "user" z user) (p "CP" "agent" z agent) (p "CP" "total" z total)
           (p "CP" "ocm" z (hash "open" "checkout" item merchant (pubk agent) (enc (hash "open" "checkout" item merchant (pubk agent)) (privk user))))
           (p "CP" "nc" z nc) (p "CP" "ch" z ch)
           (p "TS" z-0 6)
           (p "TS" "user" z-0 user) (p "TS" "agent" z-0 agent) (p "TS" "total" z-0 total)
           (p "TS" "item" z-0 item) (p "TS" "merchant" z-0 merchant)
           (non (privk user)) (uniq-at nc z 1) (auth ch) (conf ch))
      (and (p "TS" "nc1" z-0 nc) (p "TS" "ch1" z-0 ch)
           (prec z 1 z-0 2) (prec z-0 3 z 2))))
  (comment "SG3-R non-vacuity"))

;; SG3-U from the scripted fan-out, as in ap2_fanout_goals.scm, with the CP strands
;; at k_tok = 4. orig_M; no assumption on (privk agent). Expect no shapes: the
;; scripted fan-out cannot occur.
(defgoal ap2
  (forall ((zf zm1 zm2 zc1 zc2 strd) (user agent merchant cp1 cp2 name)
           (item total t1 t2 data) (o1 o2 n1 n2 text))
    (implies
      (and (p "fanout" zf 12)
           (p "fanout" "user" zf user) (p "fanout" "agent" zf agent)
           (p "fanout" "merchant" zf merchant)
           (p "fanout" "cp1" zf cp1) (p "fanout" "cp2" zf cp2)
           (p "fanout" "item" zf item) (p "fanout" "total" zf total)
           (p "fanout" "t1" zf t1) (p "fanout" "t2" zf t2)
           (p "fanout" "o1" zf o1) (p "fanout" "o2" zf o2)
           (p "fanout" "n1" zf n1) (p "fanout" "n2" zf n2)
           (p "merchant" zm1 3)
           (p "merchant" "user" zm1 user) (p "merchant" "agent" zm1 agent)
           (p "merchant" "merchant" zm1 merchant) (p "merchant" "cp" zm1 cp1)
           (p "merchant" "item" zm1 item) (p "merchant" "total" zm1 total)
           (p "merchant" "token" zm1 t1) (p "merchant" "orderId" zm1 o1)
           (p "merchant" "n1" zm1 n1)
           (p "merchant" zm2 3)
           (p "merchant" "user" zm2 user) (p "merchant" "agent" zm2 agent)
           (p "merchant" "merchant" zm2 merchant) (p "merchant" "cp" zm2 cp2)
           (p "merchant" "item" zm2 item) (p "merchant" "total" zm2 total)
           (p "merchant" "token" zm2 t2) (p "merchant" "orderId" zm2 o2)
           (p "merchant" "n1" zm2 n2)
           (p "CP" zc1 4) (p "CP" zc2 4)
           (p "CP" "user" zc1 user) (p "CP" "user" zc2 user)
           (p "CP" "agent" zc1 agent) (p "CP" "agent" zc2 agent)
           (p "CP" "total" zc1 total) (p "CP" "total" zc2 total)
           (p "CP" "ocm" zc1 (hash "open" "checkout" item merchant (pubk agent) (enc (hash "open" "checkout" item merchant (pubk agent)) (privk user))))
           (p "CP" "ocm" zc2 (hash "open" "checkout" item merchant (pubk agent) (enc (hash "open" "checkout" item merchant (pubk agent)) (privk user))))
           (p "CP" "cp" zc1 cp1) (p "CP" "cp" zc2 cp2)
           (p "CP" "token" zc1 t1) (p "CP" "token" zc2 t2)
           (p "CP" "n1" zc1 n1) (p "CP" "n1" zc2 n2)
           (p "CP" "txId" zc1 (hash item merchant o1 (enc (hash item merchant o1) (privk merchant))))
           (p "CP" "txId" zc2 (hash item merchant o2 (enc (hash item merchant o2) (privk merchant))))
           (non (privk user)) (non (privk merchant)) (non (privk cp1)) (non (privk cp2)))
      (= zc1 zc2)))
  (comment "SG3-U, scripted fan-out"))

;; Check of the HTTPS model (not cited in the paper): the TS does not
;; authenticate its client, so a TS+ strand that answered valid cannot
;; conclude that a CP+ or CP- strand sent the query. Expect a violation.
(defgoal ap2
  (forall ((z strd) (user agent merchant name) (item total data) (nc1 text) (ch1 chan))
    (implies
      (and (p "TS" z 4)
           (p "TS" "user" z user) (p "TS" "agent" z agent) (p "TS" "merchant" z merchant)
           (p "TS" "item" z item) (p "TS" "total" z total)
           (p "TS" "nc1" z nc1) (p "TS" "ch1" z ch1)
           (non (privk user)))
      (or (exists ((z-0 strd))
            (and (p "CP" z-0 2) (p "CP" "nc" z-0 nc1) (p "CP" "ch" z-0 ch1)))
          (exists ((z-0 strd))
            (and (p "CPreject" z-0 2) (p "CPreject" "nc" z-0 nc1) (p "CPreject" "ch" z-0 ch1))))))
  (comment "HTTPS check: the TS does not authenticate its client"))
