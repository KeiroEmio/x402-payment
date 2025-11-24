export type IMasterSetup = {
	settle_admin: string
	settle_u1: string
	base_endpoint: string
	base: {
		CDP_API_KEY_ID: string
		CDP_API_KEY_SECRET: string
	}
	settle_contractAdmin: string[]
	event_endpoint: string
}

/**
 *      address from,
		uint256 usdcAmount,
		uint256 validAfter,
		uint256 validBefore,
		bytes32 nonce,
		uint8 v,
		bytes32 r,
		bytes32 s
 */

export type IEIP3009depositWithUSDCAuthorization = {
	address: string
	usdcAmount: string
	validAfter: number
	validBefore: number
	nonce: string
	v: number
	r: string
	s: string
}

export type airDrop = {
	wallet: string
	settle: string
}


export type ReflashData = {
	hash: string
	wallet: string
	SETTLE: string
	USDC: string
	timestmp: string
}

type ISettleEvent = {
	from: string
	amount: string
	SETTLTAmount: string
	txHash: string
}

// ============================================
// EIP-712 typedData
// ============================================
export type EIP712 = {
	types: string
	primaryType: string
	domain: {
		chainId: number
		name: string
		verifyingContract: string
		version: string
	}
	message: {
		from: string
		to: string
		value: string
		validAfter: number
		validBefore: number
		nonce: string
	}
}

export type x402SettleResponse = {
	network: string
	payer: string
	success: boolean
	transaction: string
}

export type x402Response = {
	timestamp: string
	network: string
	payer: string
	success: boolean
	USDC_tx?: string
	SETTLE_tx?: string
}

export type payload = {

	signature: string
	authorization: {
		from: string
		to: string
		value: string
		validAfter: string
		validBefore: string
		nonce: string
	}


}

export type x402paymentHeader = {
	x402Version: number
	scheme: 'exact',
	network: string
	payload: payload
}


export type facilitatorsPoolType = {
	from: string
	value: string
	validAfter: string
	validBefore: string
	nonce: string
	signature: string
	res: any
}


export type body402 = {
	EIP712: EIP712
	sig: string
}

export type SignatureComponents = {
    v: number
    r: string
    s: string
    recoveredAddress: string
    isValid: boolean
}

// 402 Payment Required 响应体（客户端 client.getApi().PaymentRequired）
// 与服务器 verifyPayment 返回的 JSON 结构对齐：包含协议版本与可接受的支付方案。
// 可选字段用于携带错误原因与建议付款者地址（例如验证阶段返回的 payer）。
import type { PaymentRequirements } from "x402/types"
export type PaymentRequired = {
    x402Version: number
    accepts: PaymentRequirements[]
    error?: unknown
    payer?: string
    // 可选：便于追踪与容错的附加信息
    requestId?: string
    serverTime?: number // unix 秒级时间戳
}