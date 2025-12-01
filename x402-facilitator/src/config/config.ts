export interface ERC20TokenAmount {
    amount: string
    asset: {
        address: string
        decimals: number
        eip712: { name: string; version: string }
    }
}

export interface SPLTokenAmount {
    amount: string
    asset: { address: string; decimals: number }
}

export type Price = number | string | ERC20TokenAmount | SPLTokenAmount

export type Network = "rei" | "base" | "baseSepolia";

interface RouteConfig {
    price: Price
    network: Network
}

export type RoutesConfig = Record<string, Price | RouteConfig>

export interface RoutePattern {
    verb: string
    pattern: RegExp
    config: RouteConfig
}


