
type Chain = {
    id: number
    rpcUrl: string
    isEvm: boolean
    currency: string
    blockExplorerUrl?: string
    blockExplorerTxUrl?: string
}

export function getChain(network: string): Chain {
    switch (network) {
        case 'rei':
            return {
                id: 84532,
                rpcUrl: 'https://rpc.ankr.com/eth_goerli',
                isEvm: true,
                currency: 'rei',
                blockExplorerUrl: 'https://goerli.etherscan.io',
                blockExplorerTxUrl: 'https://goerli.etherscan.io/tx/$TRANSACTION_HASH',
            };
        case 'bsc':
            return {
                id: 56,
                rpcUrl: 'https://rpc.ankr.com/bsc',
                isEvm: true,
                currency: 'BNB',
                blockExplorerUrl: 'https://testnet.bscscan.com',
                blockExplorerTxUrl: 'https://testnet.bscscan.com/tx/$TRANSACTION_HASH',
            };
        case 'bsc-nsepolia':
            return {
                id: 97,
                rpcUrl: 'https://rpc.ankr.com/bsc_testnet_chapel',
                isEvm: true,
                currency: 'tBNB',
                blockExplorerUrl: 'https://testnet.bscscan.com',
                blockExplorerTxUrl: 'https://testnet.bscscan.com/tx/$TRANSACTION_HASH',
            };
        case 'solana':
            return {
                id: 101,
                rpcUrl: 'https://rpc.ankr.com/solana',
                isEvm: false,
                currency: 'SOL',
                blockExplorerUrl: 'https://explorer.solana.com',
                blockExplorerTxUrl: 'https://explorer.solana.com/tx/$TRANSACTION_HASH',
            };
        default:
            throw new Error(`Unsupported network: ${network}`);
    }
}