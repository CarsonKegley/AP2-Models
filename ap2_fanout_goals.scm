(herald "AP2 with a compromised agent (Sigma_AP2^F): security goals")
;; Generated for the AP2 formal-methods section. CPSA 4.4.9.
;; One of three models, one per strand space: ap2_goals.scm (Sigma_AP2),
;; ap2_fanout_goals.scm (Sigma_AP2^F) and fanoutFix_goals.scm (Sigma_AP2^+).
;; The protocol is the one in ap2_goals.scm plus the fanout role, a compromised
;; agent that obtains one authorization and completes two purchases with it.

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

)


;; SG3-U from the scripted fan-out: a full-height fanout strand, its two merchant
;; strands, and the CP strands that issued their tokens (k_tok = 2), which are the
;; ones with the merchants' closed-mandate nonces and transaction identifiers. The CP
;; strands have the same (U, A, total, y), so SG3-U requires them to be one strand.
;; orig_M = Non(sk U), Non(sk M), Non(sk C) for both CPs; the roles uniquely
;; originate the order identifiers and tokens. No assumption on (privk agent).
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
           (p "CP" zc1 2) (p "CP" zc2 2)
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

;; The same goal with (privk agent) non-originating: the agent keeps its key secret
;; and departs from the specification only by reusing the open mandates.
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
           (p "CP" zc1 2) (p "CP" zc2 2)
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
           (non (privk user)) (non (privk merchant)) (non (privk cp1)) (non (privk cp2))
           (non (privk agent)))
      (= zc1 zc2)))
  (comment "SG3-U, scripted fan-out, agent key secret"))
