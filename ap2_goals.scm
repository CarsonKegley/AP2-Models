(herald "AP2 specification (Sigma_AP2): security goals, agent key not assumed secret")
;; Generated for the AP2 formal-methods section. CPSA 4.4.9.
;; One of three models, one per strand space: ap2_goals.scm (Sigma_AP2),
;; ap2_fanout_goals.scm (Sigma_AP2^F) and fanoutFix_goals.scm (Sigma_AP2^+).


(defmacro (checkoutJwt item merchant orderId)
  (cat item merchant orderId
       (enc (hash item merchant orderId) (privk merchant))))

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

(defprotocol ap2 basic
    ;;The TS stands in for the user.

    (defrole TS
        (vars (user agent merchant name) (item total data))
        (trace
               (recv  (cat item merchant total (pubk agent)))
               (send (cat
                        (openCheckoutMandate item merchant user agent)
                        (openPaymentMandate total
                            (hash (openCheckoutMandate item merchant user agent))  user agent)))
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
      (vars (user agent cp name) (total token data) (n1 text) (txId ocm mesg))
      (trace
        (recv (cat (openPaymentMandate total ocm user agent)
                   (closedPaymentMandate n1 total txId
                     (openPaymentMandate total ocm user agent) agent)))
        (send (paymentToken token
                (closedPaymentMandate n1 total txId
                  (openPaymentMandate total ocm user agent) agent)
                cp)))
      (uniq-orig token))
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
             (p "CP" z-1 2)
             (p "CP" "user" z-1 user) (p "CP" "agent" z-1 agent) (p "CP" "cp" z-1 cp)
             (p "CP" "total" z-1 total) (p "CP" "n1" z-1 n1) (p "CP" "token" z-1 token)
             (p "CP" "txId" z-1 (hash item merchant orderId (enc (hash item merchant orderId) (privk merchant))))
             (p "CP" "ocm" z-1 (hash "open" "checkout" item merchant (pubk agent) (enc (hash "open" "checkout" item merchant (pubk agent)) (privk user))))))))
  (comment "SG1-M and SG2"))

;; SG1-C, accepting-CP view (k_acc = 2), orig_C = Non(sk U), Non(sk C), Uniq(t).
(defgoal ap2
  (forall ((z strd) (user agent cp name) (total token data) (ocm mesg))
    (implies
      (and (p "CP" z 2)
           (p "CP" "user" z user) (p "CP" "agent" z agent) (p "CP" "cp" z cp)
           (p "CP" "total" z total) (p "CP" "ocm" z ocm) (p "CP" "token" z token)
           (non (privk user)) (non (privk cp)) (uniq-at token z 1))
      (exists ((z-0 strd) (item data) (merchant name))
        (and (p "TS" z-0 2)
             (p "TS" "user" z-0 user) (p "TS" "agent" z-0 agent) (p "TS" "total" z-0 total)
             (p "TS" "item" z-0 item) (p "TS" "merchant" z-0 merchant)
             (= ocm (hash "open" "checkout" item merchant (pubk agent) (enc (hash "open" "checkout" item merchant (pubk agent)) (privk user))))))))
  (comment "SG1-C"))

;; SG3-U, single use: two accepting CP strands with the same (U, A, total, y) are one strand.
;; orig_C for both strands.
(defgoal ap2
  (forall ((z1 z2 strd) (user agent cp1 cp2 name) (total t1 t2 data) (ocm mesg))
    (implies
      (and (p "CP" z1 2) (p "CP" z2 2)
           (p "CP" "user" z1 user) (p "CP" "user" z2 user)
           (p "CP" "agent" z1 agent) (p "CP" "agent" z2 agent)
           (p "CP" "total" z1 total) (p "CP" "total" z2 total)
           (p "CP" "ocm" z1 ocm) (p "CP" "ocm" z2 ocm)
           (p "CP" "cp" z1 cp1) (p "CP" "cp" z2 cp2)
           (p "CP" "token" z1 t1) (p "CP" "token" z2 t2)
           (non (privk user)) (non (privk cp1)) (non (privk cp2))
           (uniq-at t1 z1 1) (uniq-at t2 z2 1))
      (= z1 z2)))
  (comment "SG3-U"))
