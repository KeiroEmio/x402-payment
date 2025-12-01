import { Chain } from 'viem'
import { base, baseSepolia, mainnet, polygon, polygonAmoy, rei } from 'viem/chains'
import { Network } from './config'

// "rei" | "base" | "baseSepolia"
export const chainMap = {
    rei,
    'baseSepolia': baseSepolia,
    base,
} as const satisfies Record<Network, Chain>