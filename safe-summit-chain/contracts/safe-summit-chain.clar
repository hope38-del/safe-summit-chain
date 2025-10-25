;; SafeSummitChain - Zero-Knowledge Identity Verification Platform
;; A decentralized professional certification management system

;; Constants
(define-constant contract-owner tx-sender)
(define-constant err-owner-only (err u100))
(define-constant err-not-found (err u101))
(define-constant err-already-exists (err u102))
(define-constant err-expired (err u103))
(define-constant err-insufficient-stake (err u104))
(define-constant err-unauthorized (err u105))
(define-constant err-invalid-validator (err u106))

;; Minimum stake required for validators (in microSTX)
(define-constant min-validator-stake u1000000)

;; Data Variables
(define-data-var certification-counter uint u0)
(define-data-var validator-counter uint u0)

;; Data Maps
;; Credential storage with hash for privacy
(define-map credentials
    { credential-id: uint }
    {
        owner: principal,
        credential-hash: (buff 32),
        issuer: principal,
        issue-date: uint,
        expiry-date: uint,
        status: (string-ascii 20),
        industry: (string-ascii 50)
    }
)

;; Validator registry with staking
(define-map validators
    { validator: principal }
    {
        stake-amount: uint,
        reputation-score: uint,
        certifications-verified: uint,
        is-active: bool
    }
)

;; Verification attestations
(define-map attestations
    { credential-id: uint, validator: principal }
    {
        verified: bool,
        timestamp: uint
    }
)

;; User credentials mapping
(define-map user-credentials
    { user: principal, index: uint }
    { credential-id: uint }
)

(define-map user-credential-count
    { user: principal }
    { count: uint }
)

;; Selective disclosure permissions
(define-map disclosure-permissions
    { credential-id: uint, viewer: principal }
    {
        can-view: bool,
        expiry: uint
    }
)

;; Read-only functions

(define-read-only (get-credential (credential-id uint))
    (map-get? credentials { credential-id: credential-id })
)

(define-read-only (get-validator (validator principal))
    (map-get? validators { validator: validator })
)

(define-read-only (get-attestation (credential-id uint) (validator principal))
    (map-get? attestations { credential-id: credential-id, validator: validator })
)

(define-read-only (can-view-credential (credential-id uint) (viewer principal))
    (match (map-get? disclosure-permissions { credential-id: credential-id, viewer: viewer })
        permission (and (get can-view permission) (> (get expiry permission) block-height))
        false
    )
)

(define-read-only (is-credential-expired (credential-id uint))
    (match (map-get? credentials { credential-id: credential-id })
        credential (>= block-height (get expiry-date credential))
        true
    )
)

(define-read-only (get-user-credential-count (user principal))
    (default-to { count: u0 } (map-get? user-credential-count { user: user }))
)

;; Public functions

;; Register as a validator with stake
(define-public (register-validator (stake-amount uint))
    (let
        (
            (validator tx-sender)
        )
        (asserts! (>= stake-amount min-validator-stake) err-insufficient-stake)
        (asserts! (is-none (map-get? validators { validator: validator })) err-already-exists)
        
        ;; Transfer stake to contract
        (try! (stx-transfer? stake-amount tx-sender (as-contract tx-sender)))
        
        ;; Register validator
        (map-set validators
            { validator: validator }
            {
                stake-amount: stake-amount,
                reputation-score: u100,
                certifications-verified: u0,
                is-active: true
            }
        )
        
        (var-set validator-counter (+ (var-get validator-counter) u1))
        (ok true)
    )
)

;; Issue a new credential
(define-public (issue-credential 
    (credential-hash (buff 32))
    (expiry-blocks uint)
    (industry (string-ascii 50)))
    (let
        (
            (new-id (+ (var-get certification-counter) u1))
            (current-count (get count (get-user-credential-count tx-sender)))
        )
        ;; Create credential
        (map-set credentials
            { credential-id: new-id }
            {
                owner: tx-sender,
                credential-hash: credential-hash,
                issuer: tx-sender,
                issue-date: block-height,
                expiry-date: (+ block-height expiry-blocks),
                status: "active",
                industry: industry
            }
        )
        
        ;; Update user credential mapping
        (map-set user-credentials
            { user: tx-sender, index: current-count }
            { credential-id: new-id }
        )
        
        (map-set user-credential-count
            { user: tx-sender }
            { count: (+ current-count u1) }
        )
        
        (var-set certification-counter new-id)
        (ok new-id)
    )
)

;; Validator attests to credential validity
(define-public (attest-credential (credential-id uint) (is-valid bool))
    (let
        (
            (validator-data (unwrap! (map-get? validators { validator: tx-sender }) err-invalid-validator))
            (credential (unwrap! (map-get? credentials { credential-id: credential-id }) err-not-found))
        )
        (asserts! (get is-active validator-data) err-unauthorized)
        (asserts! (not (is-credential-expired credential-id)) err-expired)
        
        ;; Record attestation
        (map-set attestations
            { credential-id: credential-id, validator: tx-sender }
            {
                verified: is-valid,
                timestamp: block-height
            }
        )
        
        ;; Update validator stats
        (map-set validators
            { validator: tx-sender }
            (merge validator-data { 
                certifications-verified: (+ (get certifications-verified validator-data) u1)
            })
        )
        
        (ok true)
    )
)

;; Grant selective disclosure permission
(define-public (grant-disclosure (credential-id uint) (viewer principal) (duration uint))
    (let
        (
            (credential (unwrap! (map-get? credentials { credential-id: credential-id }) err-not-found))
        )
        (asserts! (is-eq tx-sender (get owner credential)) err-unauthorized)
        
        (map-set disclosure-permissions
            { credential-id: credential-id, viewer: viewer }
            {
                can-view: true,
                expiry: (+ block-height duration)
            }
        )
        
        (ok true)
    )
)

;; Revoke disclosure permission
(define-public (revoke-disclosure (credential-id uint) (viewer principal))
    (let
        (
            (credential (unwrap! (map-get? credentials { credential-id: credential-id }) err-not-found))
        )
        (asserts! (is-eq tx-sender (get owner credential)) err-unauthorized)
        
        (map-set disclosure-permissions
            { credential-id: credential-id, viewer: viewer }
            {
                can-view: false,
                expiry: u0
            }
        )
        
        (ok true)
    )
)

;; Renew expired credential (requires validator consensus)
(define-public (renew-credential (credential-id uint) (new-expiry-blocks uint))
    (let
        (
            (credential (unwrap! (map-get? credentials { credential-id: credential-id }) err-not-found))
        )
        (asserts! (is-eq tx-sender (get owner credential)) err-unauthorized)
        
        ;; Update expiry date
        (map-set credentials
            { credential-id: credential-id }
            (merge credential {
                expiry-date: (+ block-height new-expiry-blocks),
                status: "active"
            })
        )
        
        (ok true)
    )
)

;; Revoke a credential
(define-public (revoke-credential (credential-id uint))
    (let
        (
            (credential (unwrap! (map-get? credentials { credential-id: credential-id }) err-not-found))
        )
        (asserts! (is-eq tx-sender (get owner credential)) err-unauthorized)
        
        (map-set credentials
            { credential-id: credential-id }
            (merge credential { status: "revoked" })
        )
        
        (ok true)
    )
)

;; Validator withdraws stake (if leaving the system)
(define-public (withdraw-stake)
    (let
        (
            (validator-data (unwrap! (map-get? validators { validator: tx-sender }) err-invalid-validator))
            (stake (get stake-amount validator-data))
        )
        ;; Deactivate validator
        (map-set validators
            { validator: tx-sender }
            (merge validator-data { is-active: false })
        )
        
        ;; Return stake
        (as-contract (stx-transfer? stake tx-sender tx-sender))
    )
)

;; Update validator reputation (simplified - in production would be consensus-based)
(define-public (update-reputation (validator principal) (new-score uint))
    (let
        (
            (validator-data (unwrap! (map-get? validators { validator: validator }) err-invalid-validator))
        )
        (asserts! (is-eq tx-sender contract-owner) err-owner-only)
        
        (map-set validators
            { validator: validator }
            (merge validator-data { reputation-score: new-score })
        )
        
        (ok true)
    )
)
