import { rei } from 'viem/chains';
import { PaymentPayload } from '../../types/PaymentRequired';

const SUPPORTED_CHAINS = {
    [rei.name]: rei,
} as const;

export const exactEvm = {
    decodePayment(payment: string): PaymentPayload {
        const jwt = Buffer.from(payment, 'base64').toString('utf-8');
        const paredObject = JSON.parse(jwt);

        const paymentPayload: PaymentPayload = paredObject as PaymentPayload;

        if (paymentPayload.scheme !== 'exact') throw new Error('Not exact scheme');
        if (!paymentPayload.network || !paymentPayload.payload || !paymentPayload.x402Version)
            throw new Error('Missing required fields');

        const chainName = paymentPayload.network;
        const chain = SUPPORTED_CHAINS[chainName as keyof typeof SUPPORTED_CHAINS];
        if (!chain) throw new Error(`Unsupported chainName: ${chainName}`);

        return paymentPayload;
    }
};