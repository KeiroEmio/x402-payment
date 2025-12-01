import { Signature } from 'ethers';
import { Sign } from 'node:crypto';
import { Address, Hex } from 'viem';

export type Network =
    | "rei"
    | "bsc"
    | "bsc-nsepolia"
    | "eth"
    | "eth-sepolia"

export type Scheme = "exact" | "permit" | "solana";

export interface PaymentRequirement {
    scheme: Scheme;
    network: Network;
    maxAmountRequired: bigint;
    resource: string;
    description: string;
    mimeType: string;
    outputSchema?: Record<string, any>;
    payTo: Address;
    maxTimeoutSeconds: number;
    asset: Address;
    extra?: Record<string, any>;
}

//Compliant with EIP3009 standard
export type PaymentPayload = {
    scheme: Scheme;
    network: Network;
    x402Version: number;
    payload:
    | {
        signature: string;
        authorization: {
            from: Address;
            to: Address;
            value: bigint;
            validAfter: number;
            validBefore: number;
            nonce: string;
        };
    }
    //Compliant with EIP1271 standard for solana
    | {
        transaction: Hex;
    };
};

const selectPaymentRequirement: PaymentRequirementsSelector = (requirements, network, scheme) => {
    return requirements.find(r =>
        (!network || r.network === network || (Array.isArray(r.network) && r.network.includes(network))) &&
        (!scheme || r.scheme === scheme)
    )!;
};

export type VerifyResponse = {
    x402Version: number;
    isValid: boolean;
    error?: string;
    payer?: Address;
    accepts?: Array<{
        scheme: "exact";
        description: string;
        asset: Address;
        maxAmountRequired: string;
        network: Network;
        resource: string;
        mimeType: string;
        payTo: Address;
        maxTimeoutSeconds: number;
        outputSchema?: Record<string, any>;
        extra?: Record<string, any>;
    }>;
};

// 生成 EIP-712 签名 (ethers.js)
// const domain = { name: 'USD Coin', version: '2', chainId: 8453, verifyingContract: USDC_ADDRESS };
// const message = { from: userAddress, to: merchantAddress, value: ethers.parseUnits('1', 6), nonce: randomBytes32, validAfter: 0, validBefore: maxUint256 };
// const signature = await wallet.signTypedData(domain, { TransferWithAuthorization: [...] }, message);  // EIP-3009 payload