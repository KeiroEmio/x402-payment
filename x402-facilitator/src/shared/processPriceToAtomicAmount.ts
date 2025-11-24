import { getDefaultAsset } from './index'
import { Network, Price, ERC20TokenAmount, SPLTokenAmount } from '../config/config'

function parseMoney(price: string | number): number | null {
    if (typeof price === 'number') {
        if (!Number.isFinite(price)) return null
        return price
    }
    const s = String(price).trim()
    const cleaned = s.startsWith('$') ? s.slice(1).trim() : s
    const n = Number(cleaned)
    if (!Number.isFinite(n)) return null
    return n
}

// Process a price to get the max amount required in atomic units (e.g. wei for Ethereum)
export function processPriceToAtomicAmount(
    price: Price,
    network: Network
): { maxAmountRequired: string; asset: ERC20TokenAmount['asset'] | SPLTokenAmount['asset'] } | { error: string } {
    let maxAmountRequired: string
    let asset: ERC20TokenAmount['asset'] | SPLTokenAmount['asset']

    if (typeof price === 'string' || typeof price === 'number') {
        const parsedUsdAmount = parseMoney(price)
        if (parsedUsdAmount === null) {
            return { error: `Invalid price (price: ${price}). Must be a number or string like "$3.10" or "0.001"` }
        }
        asset = getDefaultAsset(network) as ERC20TokenAmount['asset']
        maxAmountRequired = (parsedUsdAmount * 10 ** asset.decimals).toString()
    } else {
        maxAmountRequired = price.amount
        asset = price.asset
    }

    return { maxAmountRequired, asset }
}

// export function findMatchingPaymentRequirements(
//     paymentRequirements: PaymentRequirement,
//     paymentPayload: PaymentPayload
// ): (PaymentRequirement | Price)[] {
//     return Object.values(paymentRequirements).filter((req) => {
//         if (typeof req === 'object' && req.network === paymentPayload.network) return true
//         if (typeof req === 'string' || typeof req === 'number') return true
//         return false
//     })
// }
