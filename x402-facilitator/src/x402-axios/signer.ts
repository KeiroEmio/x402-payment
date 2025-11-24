import { privateKeyToAccount } from 'viem/accounts';
import { getChainConfig } from './chains';
import type { ISigner } from './types';
import { Hex } from 'viem';
import { EvmSigner, SvmSigner } from './types';
import { Keypair } from '@solana/web3.js';

/**
 * Create a signer instance for signing payments.
 * @param network - The network name, e.g. "rei"
 * @param privateKey - The private key for signing payments
 * @returns A signer instance for signing payments
 */

export function createSigner(network: string, privateKey: Hex, options?: { rpcUrl?: string }): ISigner {
    const chain = getChainConfig(network);
    chain.rpcUrl = options?.rpcUrl || chain.rpcUrl;
    if (chain.isEvm) {
        const account = privateKeyToAccount(privateKey);
        return new EvmSigner(account, chain.rpcUrl, chain.id, chain.currency, chain.blockExplorerUrl || '', chain.blockExplorerTxUrl || '');
    } else {
        const secretKey = typeof privateKey === 'string'
            ? Uint8Array.from(JSON.parse(privateKey))
            : privateKey;
        const keypair = Keypair.fromSecretKey(secretKey);
        return new SvmSigner(keypair);
    }
}