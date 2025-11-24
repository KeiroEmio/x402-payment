
type Chain = {
    id: number
    rpcUrl: string
    isEvm: boolean
    nativeToken: string
}

export function getChain(network: string): Chain {
    switch (network) {
        case 'rei':
            return {
                id: 84532,
                rpcUrl: 'https://rpc.ankr.com/eth_goerli',
                isEvm: true,
                nativeToken: 'rei',
            };
        case 'bsc':
            return {
                id: 56,
                rpcUrl: 'https://rpc.ankr.com/bsc',
                isEvm: true,
                nativeToken: 'bnb',
            };
        case 'bsc-nsepolia':
            return {
                id: 97,
                rpcUrl: 'https://rpc.ankr.com/bsc_testnet_chapel',
                isEvm: true,
                nativeToken: 'tBnb',
            };
        case 'solana':
            return {
                id: 101,
                rpcUrl: 'https://rpc.ankr.com/solana',
                isEvm: false,
                nativeToken: 'sol',
            };
        default:
            throw new Error(`Unsupported network: ${network}`);
    }
}