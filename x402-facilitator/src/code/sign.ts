import { ethers } from 'ethers'
import { PaymentRequirement } from '../types/PaymentRequired'

const EIP3009_TYPES = {
    TransferWithAuthorization: [
        { name: 'from', type: 'address' },
        { name: 'to', type: 'address' },
        { name: 'value', type: 'uint256' },
        { name: 'validAfter', type: 'uint256' },
        { name: 'validBefore', type: 'uint256' },
        { name: 'nonce', type: 'bytes32' },
    ],
    EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
    ],
}

export async function signWithMetaMask(req: PaymentRequirement) {
    const ethereum = (window as any).ethereum
    const [from] = await ethereum.request({ method: 'eth_requestAccounts' })
    const chainIdHex = await ethereum.request({ method: 'eth_chainId' })
    const chainId = Number(chainIdHex)
    const now = Math.floor(Date.now() / 1000)
    const message = {
        from,
        to: req.payTo,
        value: req.maxAmountRequired,
        validAfter: now,
        validBefore: now + req.maxTimeoutSeconds,
        nonce: ethers.hexlify(ethers.randomBytes(32)) as `0x${string}`,
    }
    const domain = { name: 'USD Coin', version: '2', chainId, verifyingContract: req.asset }
    const typedData = {
        types: EIP3009_TYPES,
        domain,
        primaryType: 'TransferWithAuthorization',
        message,
    }
    const signature: string = await ethereum.request({
        method: 'eth_signTypedData_v4',
        params: [from, JSON.stringify(typedData)],
    })
    return {
        authorization: { ...message, signature },
        asset: req.asset,
        network: req.network,
        domain,
    }
}

export async function signWithPrivateKey(req: PaymentRequirement, privateKey: string, chainId: number) {
    const wallet = new ethers.Wallet(privateKey)
    const from = await wallet.getAddress()
    const now = Math.floor(Date.now() / 1000)
    const message = {
        from,
        to: req.payTo,
        value: req.maxAmountRequired,
        validAfter: now,
        validBefore: now + req.maxTimeoutSeconds,
        nonce: ethers.hexlify(ethers.randomBytes(32)) as `0x${string}`,
    }
    const domain = { name: 'USD Coin', version: '2', chainId, verifyingContract: req.asset }
    const signature = await wallet.signTypedData(domain, EIP3009_TYPES as any, message)
    return {
        authorization: { ...message, signature },
        asset: req.asset,
        network: req.network,
        domain,
    }
}