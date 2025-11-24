import { Keypair, Transaction, VersionedTransaction } from '@solana/web3.js';
import {
    createWalletClient,
    http,
    Hex,
    TransactionRequest,
    signTypedData,
    createPublicClient,
    Account,
    WalletClient,
    PublicClient
} from 'viem';
import { mainnet } from 'viem/chains';
import bs58 from 'bs58';
import nacl from 'tweetnacl';
import { PaymentRequirement } from '../types/PaymentRequired';
import { getChainConfig } from './chains';
import { erc20Abi } from './abis/erc20';

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
    offSignTransaction(paymentRequirement: PaymentRequirement): Promise<any>;
}

export class EvmSigner implements ISigner {
    private account: Account;
    private walletClient: WalletClient;
    private publicClient: PublicClient;

    constructor(account: Account, rpcUrl: string, chainId: number, currency: string, blockExplorerUrl: string, blockExplorerTxUrl: string) {
        this.account = account;
        this.walletClient = createWalletClient({
            chain: {
                ...mainnet,
                id: chainId,
                currency: currency,
                blockExplorerUrl: blockExplorerUrl,
                blockExplorerTxUrl: blockExplorerTxUrl,
            },
            transport: http(rpcUrl),
            account: this.account
        });
        this.publicClient = createPublicClient({
            chain: {
                ...mainnet,
                id: chainId,
                currency: currency,
                blockExplorerUrl: blockExplorerUrl,
                blockExplorerTxUrl: blockExplorerTxUrl,
            },
            transport: http(rpcUrl),
        });
    }

    async sign(data: any): Promise<Hex> {
        return await this.walletClient.signTypedData(data);
    }

    async getAddress(): Promise<string> {
        return this.account.address;
    }

    async offSignTransaction(paymentRequirement: PaymentRequirement): Promise<Hex> {
        if (!paymentRequirement.payTo || !paymentRequirement.asset || paymentRequirement.maxAmountRequired <= 0n) {
            throw new Error('Invalid PaymentRequirement: missing payTo, asset, or maxAmountRequired');
        }
        const chain = getChainConfig(paymentRequirement.network);
        const now = BigInt(Math.floor(Date.now() / 1000));
        const nonce = await this.publicClient.readContract({
            address: paymentRequirement.asset,
            abi: erc20Abi,
            functionName: 'nonces',
            args: [this.account.address],
        }) as bigint;

        const message = {
            from: this.account.address,
            to: paymentRequirement.payTo,
            value: paymentRequirement.maxAmountRequired,
            validAfter: now,
            validBefore: now + BigInt(paymentRequirement.maxTimeoutSeconds),
            nonce,
        };

        //         domain: {
        //    *     name: 'Ether Mail',
        //    *     version: '1',
        //    *     chainId: 1,
        //    *     verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
        //    *   },
        const domain = {
            name: paymentRequirement.extra!.name || 'USDC',  // 'USDC'
            version: paymentRequirement.extra!.version || '2',  // '2'
            chainId: Number(chain.id),
            verifyingContract: paymentRequirement.asset,
        };

        // TransactionRequest

        const types = {
            TransferWithAuthorization: [
                { name: 'from', type: 'address' },
                { name: 'to', type: 'address' },
                { name: 'value', type: 'uint256' },
                { name: 'validAfter', type: 'uint256' },
                { name: 'validBefore', type: 'uint256' },
                { name: 'nonce', type: 'uint256' },
            ],
        };
        const signature = await this.walletClient.signTypedData({
            domain,
            account: this.account,
            // domain,
            types,
            primaryType: 'TransferWithAuthorization',
            message,
        });
        return signature;
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

    async offSignTransaction(tx: PaymentRequirement): Promise<void> {
        // if (tx instanceof VersionedTransaction) {
        //     tx.sign([this.keypair]);
        //     return tx.signatures.map(sig => sig ? bs58.encode(sig) : '');
        // } else {
        //     tx.partialSign(this.keypair);
        //     return tx.signatures
        //         .filter(s => s.signature !== null)
        //         .map(s => bs58.encode(s.signature!));
        // }
    }
}