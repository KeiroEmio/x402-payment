export type Scheme = "exact";

export type Network =
    | "rei"
    | "bsc"
    | "bsc-nsepolia"
    | "eth"
    | "eth-sepolia"

export type Hex = `0x${string}`;

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
    asset: Hex;
    extra?: Record<string, any>;
}

export interface Authorization3009 {
    from: Address;
    to: Address;
    value: string;
    validAfter: number;
    validBefore: number;
    nonce: HexString;
    signature?: HexString;
    v?: number;
    r?: HexString;
    s?: HexString;
}

export interface PaymentDomain {
    name?: string;
    version?: string;
    chainId?: number;
    verifyingContract?: Address;
    salt?: HexString;
}

export interface PaymentPayload {
    authorization: Authorization3009;
    asset: string;
    network: string;
    domain?: PaymentDomain;
    x402Version?: number;
    requirementsId?: string;
    facilitator?: Address;
    createdAt?: number;
}

const selectPaymentRequirement: PaymentRequirementsSelector = (requirements, network, scheme) => {
    return requirements.find(r =>
        (!network || r.network === network || (Array.isArray(network) && network.includes(r.network))) &&
        (!scheme || r.scheme === scheme)
    )!;
};