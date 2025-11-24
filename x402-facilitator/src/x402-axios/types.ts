import { Keypair, Transaction, VersionedTransaction } from '@solana/web3.js';
import {
    createWalletClient,
    http,
    Hex,
    TransactionRequest,
    Account,
    WalletClient
} from 'viem';
import { mainnet } from 'viem/chains';
import bs58 from 'bs58';
import nacl from 'tweetnacl';

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
    offSignTransaction(tx: any): Promise<any>;
}

export class EvmSigner implements ISigner {
    private account: Account;
    private walletClient: WalletClient;

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
    }

    async sign(data: any): Promise<Hex> {
        return await this.walletClient.signTypedData(data);
    }

    async getAddress(): Promise<string> {
        return this.account.address;
    }

    async offSignTransaction(tx: TransactionRequest): Promise<Hex> {
        const params = {
            account: this.account.address,
            request: { ...tx },
            chain: this.walletClient.chain,
        };
        return await this.walletClient.signTransaction(params);
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

    async offSignTransaction(tx: Transaction | VersionedTransaction): Promise<string[]> {
        if (tx instanceof VersionedTransaction) {
            tx.sign([this.keypair]);
            return tx.signatures.map(sig => sig ? bs58.encode(sig) : '');
        } else {
            tx.partialSign(this.keypair);
            return tx.signatures
                .filter(s => s.signature !== null)
                .map(s => bs58.encode(s.signature!));
        }
    }
}