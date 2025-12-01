import { Keypair, Transaction, VersionedTransaction } from '@solana/web3.js';
import {
    createWalletClient,
    http,
    Hex,
    TransactionRequest,
    createPublicClient,
    Account,
    WalletClient,
    Address,
    PublicClient
} from 'viem';
import bs58 from 'bs58';
import nacl from 'tweetnacl';
import { PaymentRequirement, PaymentPayload } from '../types/PaymentRequired';
import { getChainConfig } from './chains';

const eip3009Abi = [
    {
        name: 'authorizationState',
        type: 'function',
        stateMutability: 'view',
        inputs: [
            { name: 'authorizer', type: 'address' },
            { name: 'nonce', type: 'bytes32' },
        ],
        outputs: [{ name: '', type: 'bool' }],
    },
    {
        name: 'name',
        type: 'function',
        stateMutability: 'view',
        inputs: [],
        outputs: [{ name: '', type: 'string' }],
    },
    {
        name: 'version',
        type: 'function',
        stateMutability: 'view',
        inputs: [],
        outputs: [{ name: '', type: 'string' }],
    },
    {
        name: 'nonces',
        type: 'function',
        stateMutability: 'view',
        inputs: [{ name: 'owner', type: 'address' }],
        outputs: [{ name: '', type: 'uint256' }],
    }
] as const;

export interface ChainConfig {
    id: number;
    name: string;
    rpcUrl: string;
    currency: string;
    blockExplorerUrl?: string;
    blockExplorerTxUrl?: string;
}


export interface ISigner {
    sign(data: any): Promise<string>;
    getAddress(): Promise<string>;
    offSignTransaction(paymentRequirement: PaymentRequirement): Promise<string>;
}

export class EvmSigner implements ISigner {
    private account: Account;
    private walletClient: WalletClient;
    private publicClient: PublicClient;

    constructor(account: Account, rpcUrl: string, chain: string) {
        const rpcUrls: readonly string[] = [rpcUrl];
        const chainConfig = getChainConfig(chain);
        this.account = account;
        this.walletClient = createWalletClient({
            chain: {
                id: chainConfig.id,
                name: chainConfig.name,
                nativeCurrency: {
                    name: chainConfig.currency,
                    symbol: chainConfig.currency,
                    decimals: 18,
                },
                rpcUrls: {
                    default: {
                        http: rpcUrls,
                    },
                },
            },
            transport: http(rpcUrls[0]),
            account: this.account
        });
        this.publicClient = createPublicClient({
            chain: {
                id: chainConfig.id,
                name: chainConfig.name,
                nativeCurrency: {
                    name: chainConfig.currency,
                    symbol: chainConfig.currency,
                    decimals: 18,
                },
                rpcUrls: {
                    default: {
                        http: rpcUrls,
                    },
                },
            },
            transport: http(rpcUrls[0]),
        });
    }

    async sign(data: any): Promise<Hex> {
        return await this.walletClient.signTypedData(data);
    }

    async getAddress(): Promise<string> {
        return this.account.address;
    }

    async offSignTransaction(paymentRequirement: PaymentRequirement): Promise<string> {
        if (!paymentRequirement.payTo || !paymentRequirement.asset || paymentRequirement.maxAmountRequired <= 0n) {
            throw new Error('Invalid PaymentRequirement: missing payTo, asset, or maxAmountRequired');
        }
        const chain = getChainConfig(paymentRequirement.network);
        const now = BigInt(Math.floor(Date.now() / 1000));
        // 1. usdc contract get nonce for bigint (usdc support eip3009 and erc712)
        const nonce = await this.publicClient.readContract({
            address: paymentRequirement.asset,
            abi: eip3009Abi,
            functionName: 'nonces',
            args: [this.account.address as Address],
        }) as bigint;

        // 2. Constructing EIP-712 message
        const message = {
            from: this.account.address,
            to: paymentRequirement.payTo as `0x${string}`,
            value: paymentRequirement.maxAmountRequired,
            validAfter: 0n,
            validBefore: now + BigInt(paymentRequirement.maxTimeoutSeconds),
            nonce,
        };

        // 3. EIP-712 domain (read name/version from the chain, ensuring 100% accuracy)
        const [name, version] = await Promise.all([
            this.publicClient.readContract({
                address: paymentRequirement.asset,
                abi: eip3009Abi,
                functionName: 'name',
            }),
            this.publicClient.readContract({
                address: paymentRequirement.asset,
                abi: eip3009Abi,
                functionName: 'version',
            }),
        ]);

        const domain = {
            name,
            version,
            chainId: Number(chain.id),
            verifyingContract: paymentRequirement.asset,
        };

        //4. Correct EIP-3009 types 
        const types = {
            TransferWithAuthorization: [
                { name: 'from', type: 'address' },
                { name: 'to', type: 'address' },
                { name: 'value', type: 'uint256' },
                { name: 'validAfter', type: 'uint256' },
                { name: 'validBefore', type: 'uint256' },
                { name: 'nonce', type: 'uint256' },
            ],
        } as const;
        const signature = await this.walletClient.signTypedData({
            account: this.account,
            domain,
            types,
            primaryType: 'TransferWithAuthorization',
            message,
        });

        const paymentPayload = {
            scheme: "exact" as const,
            network: paymentRequirement.network,
            x402Version: 1,
            payload: {
                signature,
                authorization: {
                    from: this.account.address,
                    to: paymentRequirement.payTo,
                    value: paymentRequirement.maxAmountRequired.toString(),
                    validAfter: "0",
                    validBefore: (now + BigInt(paymentRequirement.maxTimeoutSeconds)).toString(),
                    nonce: nonce.toString(),
                }
            }
        };
        return Buffer.from(JSON.stringify(paymentPayload, (key, value) =>
            typeof value === 'bigint' ? value.toString() : value
        )).toString('base64');
    }
}

export class SvmSigner implements ISigner {
    private keypair: Keypair;

    constructor(keypair: Keypair) {
        this.keypair = keypair;
    }

    async sign(message: Uint8Array | string): Promise<string> {
        const msg = typeof message === 'string' ? new TextEncoder().encode(message) : message;
        const signature = nacl.sign.detached(msg, this.keypair.secretKey);
        return bs58.encode(signature);
    }

    async getAddress(): Promise<string> {
        return this.keypair.publicKey.toBase58();
    }

    async offSignTransaction(tx: PaymentRequirement): Promise<string> {
        // if (tx instanceof VersionedTransaction) {
        //     tx.sign([this.keypair]);
        //     return tx.signatures.map(sig => sig ? bs58.encode(sig) : '');
        // } else {
        //     tx.partialSign(this.keypair);
        //     return tx.signatures
        //         .filter(s => s.signature !== null)
        //         .map(s => bs58.encode(s.signature!));
        // }
        console.log('solana offSignTransaction not implemented');

        const jsonString = JSON.stringify({
            scheme: "solana",
            network: tx.network,
            x402Version: 1,
            payload: {
                transaction: '',
            }
        }, (key, value) =>
            typeof value === 'bigint' ? value.toString() : value
        );
        return Buffer.from(jsonString).toString('base64');
    }
}