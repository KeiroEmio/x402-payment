import { PaymentPayload, PaymentRequirement, VerifyResponse } from '../types/PaymentRequired';
import { verifyExactPayment, verifyPermitPayment, verifySolanaPayment } from './verify';
import { Facilitator } from '../types/type'
import { ethers } from 'ethers';
import { settleExactPayment, settlePermitPayment, settleSolanaPayment } from './settle';
import { Scheme } from '../types/type';
import { createWalletClient, http } from 'viem'
import { rei } from 'viem/chains'
import { facilitatorAccount } from '../config/const'
import { chainMap } from '../config/chains';

const facilitatorMapping = new Map<string, string>([
    ['key1', 'value1'],
    ['key2', 'value2']
]);

/**
 * start X402 Facilitator。
 * 
 * @param endpoint X402 node address
 * @param token Authorization token
 * @returns The initialized facilitator instance
 */
export async function createFacilitator(endpoint: string, token: string): Promise<Facilitator> {
    try {
        const facilitatorToken = facilitatorMapping.get(token)
        if (!facilitatorToken) {
            throw new Error('facilitator token not found')
        }
        return {
            endpoint,
            token: facilitatorToken,
            provider: new ethers.JsonRpcProvider(endpoint),
        }
    } catch (error) {
        console.error('Error fetching token:', error)
        throw error
    }
}

export function useFacilitator(facilitator: Facilitator) {
    const verify = async (decodePayment: PaymentPayload, selectedRequirement: PaymentRequirement): Promise<VerifyResponse> => {
        switch (selectedRequirement.scheme) {
            case Scheme.Exact:
                return verifyExactPayment(decodePayment, selectedRequirement, facilitator.provider)
            case Scheme.Permit:
                return verifyPermitPayment(decodePayment, selectedRequirement)
            case Scheme.Solana:
                return verifySolanaPayment(decodePayment, selectedRequirement)
            default:
                throw new Error('unsupported payment scheme')
        }
    };

    const settle = (decodePayment: PaymentPayload, selectedRequirement: PaymentRequirement) => {
        const chain = chainMap[selectedRequirement.network as keyof typeof chainMap];
        const client = createWalletClient({
            account: facilitatorAccount,
            chain,
            transport: http()
        })
        switch (selectedRequirement.scheme) {
            case Scheme.Exact:
                return settleExactPayment(decodePayment, selectedRequirement, facilitator.provider, client)
            case Scheme.Permit:
                return settlePermitPayment(decodePayment, selectedRequirement, client)
            case Scheme.Solana:
                return settleSolanaPayment(decodePayment, selectedRequirement, client)
            default:
                throw new Error('unsupported payment scheme')
        }
    };

    return { verify, settle };
}
