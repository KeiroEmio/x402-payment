import { Facilitator } from '../types/type'
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
        // search mysql for facilitator token

        // const response = await fetch(`${endpoint}/token`, {
        //     method: 'GET',
        //     headers: {
        //         'Authorization': `Bearer ${token}`,
        //     },
        // })
        // if (!response.ok) {
        //     throw new Error(`HTTP error! status: ${response.status}`)
        // }
        const facilitatorToken = facilitatorMapping.get(token)
        if (!facilitatorToken) {
            throw new Error('facilitator token not found')
        }
        return {
            endpoint,
            token: facilitatorToken,
        }
    } catch (error) {
        console.error('Error fetching token:', error)
        throw error
    }
}

function useFacilitator(facilitator: Facilitator) {
    const verify = (decodePayment: string) => {
        //...
    };

    const settle = () => {
        //...
    };

    return { verify, settle };
}

function createExactPaymentRequirements(create) {

    return {
        scheme: 'exact',
        asset,
        network,
        x402Version,
        requirementsId,
        facilitator,
        createdAt,
    }
}