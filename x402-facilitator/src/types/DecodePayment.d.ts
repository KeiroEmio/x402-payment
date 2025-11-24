// x402-facilitator/src/type/type.d.ts

export type HexString = `0x${string}`

export interface AuthorizationBase {
    from: string
    to: string
    value: string
    validAfter: number
    validBefore: number
    nonce: HexString
}

export interface AuthorizationWithSig extends AuthorizationBase {
    signature: HexString
}

export interface AuthorizationWithVRS extends AuthorizationBase {
    v: number
    r: HexString
    s: HexString
}

export type Authorization =
    | AuthorizationWithSig
    | AuthorizationWithVRS

export interface PaymentDomain {
    name?: string
    version?: string
    chainId?: number
    verifyingContract?: string
    salt?: HexString
}

export interface PaymentPayload {
    authorization: Authorization
    asset: string
    network: string
    domain?: PaymentDomain
    x402Version?: string
    requirementsId?: string
    facilitator?: string
    createdAt?: number
}

export type DecodePayment = (payment: string) => PaymentPayload