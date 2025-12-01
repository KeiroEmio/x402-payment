import { Network } from '../config/config'
import { PaymentPayload, PaymentRequirement } from '../types/PaymentRequired'
import { Address, Hex } from '../types/hex'
export * from './processPriceToAtomicAmount'

type Erc20Asset = {
    address: Address
    decimals: number
    eip712: { name: string; version: string }
}

const ZERO: Address = '0x0000000000000000000000000000000000000000'

const USDC_BY_NETWORK: Record<Network, Erc20Asset> = {
    rei: { address: ZERO, decimals: 6, eip712: { name: 'USD Coin', version: '2' } },
    'base-sepolia': { address: ZERO, decimals: 6, eip712: { name: 'USD Coin', version: '2' } },
    base: { address: ZERO, decimals: 6, eip712: { name: 'USD Coin', version: '2' } },
    polygon: { address: ZERO, decimals: 6, eip712: { name: 'USD Coin', version: '2' } },
    'polygon-amoy': { address: ZERO, decimals: 6, eip712: { name: 'USD Coin', version: '2' } },
    ethereum: { address: ZERO, decimals: 6, eip712: { name: 'USD Coin', version: '2' } },
}

export function getDefaultAsset(network: Network): Erc20Asset {
    const asset = USDC_BY_NETWORK[network]
    if (!asset) throw new Error(`Unable to get default asset on ${network}`)
    return asset
}

export function decodeXPaymentResponse(header: string): {
    success: boolean
    transaction: Hex
    network: Network
    payer: Address
} {
    const [success, transaction, network, payer] = header.split(',')
    return {
        success: success === 'true',
        transaction: transaction as Hex,
        network: network as Network,
        payer: payer as Address,
    }
}

export function selectPaymentRequirement(
    requirements: PaymentRequirement[],
    decodedPayment: PaymentPayload
): PaymentRequirement {
    return requirements.find(r =>
        (!decodedPayment.network || r.network === decodedPayment.network || (Array.isArray(r.network) && r.network.includes(decodedPayment.network))) &&
        (!decodedPayment.scheme || r.scheme === decodedPayment.scheme)
    )!
}
