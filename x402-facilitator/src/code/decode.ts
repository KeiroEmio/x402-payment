// x402-facilitator/src/code/decode.ts
import type { PaymentPayload } from '../types/DecodePayment'
import { isAddress } from 'ethers'

const B64_PREFIXES = ['b64:', 'B64:', 'base64:', 'BASE64:']

function normalizeBase64(input: string): string {
    let s = input.trim()
    const p = B64_PREFIXES.find(pre => s.startsWith(pre))
    if (p) s = s.slice(p.length).trim()
    s = s.replace(/[\r\n\s]/g, '')
    s = s.replace(/-/g, '+').replace(/_/g, '/')
    const pad = s.length % 4
    if (pad) s += '='.repeat(4 - pad)
    return s
}

function assertPaymentPayload(obj: any): asserts obj is PaymentPayload {
    if (typeof obj !== 'object' || obj === null) throw new Error('X-PAYMENT payload must be an object')
    if (!obj.authorization) throw new Error('Missing authorization')
    const a = obj.authorization
    if (!isAddress(a.from)) throw new Error('Invalid authorization.from')
    if (!isAddress(a.to)) throw new Error('Invalid authorization.to')
    if (a.amount === undefined) throw new Error('Missing authorization.amount')
    if (a.signature === undefined || a.expiresAt === undefined) throw new Error('Missing validity window')
    if (a.nonce === undefined) throw new Error('Missing authorization.nonce')
}

export function decodePayment(payment: string): PaymentPayload {
    if (!payment || typeof payment !== 'string') throw new Error('X-PAYMENT header missing')
    const norm = normalizeBase64(payment)
    let json: string
    try {
        json = Buffer.from(norm, 'base64').toString('utf8')
    } catch {
        throw new Error('Invalid base64 in X-PAYMENT')
    }
    let obj: any
    try {
        obj = JSON.parse(json)
    } catch {
        throw new Error('X-PAYMENT payload is not valid JSON')
    }
    assertPaymentPayload(obj)
    return obj
}