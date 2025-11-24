export type Facilitator = {
    endpoint: string
    token: string
}


export type Erc20Asset = {
    address: `0x${string}`
    decimals: number
    eip712: { name: string; version: string }
}
