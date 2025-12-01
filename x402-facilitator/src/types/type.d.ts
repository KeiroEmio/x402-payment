import { ethers } from 'ethers'
import { Network } from 'inspector/promises'

export type Facilitator = {
    endpoint: string
    token: string
    provider: ethers.Provider
}


export type Erc20Asset = {
    address: Address
    decimals: number
    eip712: { name: string; version: string }
}

const Scheme = {
    Exact: "exact",
    Permit: "permit",
    Solana: "solana",
} as const;

export const ERC20AssetMap: Record<Network, Erc20Asset> = {
    "ethereum": { address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", decimals: 6, eip712: { name: 'USD Coin', version: '2' } },
    "polygon": { address: "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174", decimals: 6, eip712: { name: 'USD Coin', version: '2' } },
    "arbitrum": { address: "0xFF970A61A04b1cA14834A43f5de4533eBDDB5CC8", decimals: 6, eip712: { name: 'USD Coin', version: '2' } },
    "optimism": { address: "0x7F5c764cBc14f9669B88837ca1490cCa17c31607", decimals: 6, eip712: { name: 'USD Coin', version: '2' } },
};

export type Domain = {
    name: string
    version: string
    chainId: number
    verifyingContract: Address
}