import { PaymentPayload, PaymentRequirement } from '../types/PaymentRequired'
import { WalletClient } from 'viem'
import { ethers } from 'ethers';
import { X402_VERSIONS } from '../types/version';
import exactTokenAbi from '../abi/baseSepolia/exactToken.json';

async function settleExactPayment(
    decodePayment: PaymentPayload,
    requirement: PaymentRequirement,
    provider: ethers.Provider,
    client: WalletClient
) {
    if (!("signature" in decodePayment.payload) || !("authorization" in decodePayment.payload)) {
        return { x402Version: X402_VERSIONS[0], isValid: false, error: "invalid_payload" };
    }

    const { authorization, signature } = decodePayment.payload!;
    const token = new ethers.Contract(requirement.asset, exactTokenAbi, provider);

    const sig = ethers.Signature.from(signature);
    // 或者手动解析 r,s,v
    // const { r, s, v } = ethers.utils.splitSignature(signature);

    // 发起链上交易
    const tx = await token.transferWithAuthorization(
        authorization.from,
        authorization.to,
        ethers.BigNumber.from(authorization.value),
        ethers.BigNumber.from(authorization.validAfter),
        ethers.BigNumber.from(authorization.validBefore),
        authorization.nonce,
        sig.v,
        sig.r,
        sig.s
    );

    // 等待交易确认
    const receipt = await tx.wait();
    return receipt;
}

async function settlePermitPayment(
    decodePayment: PaymentPayload,
    requirement: PaymentRequirement,
    client: WalletClient
) {
    // TODO: implement settlePermitPayment
}

async function settleSolanaPayment(
    decodePayment: PaymentPayload,
    selectedRequirement: PaymentRequirement,
    client: WalletClient
) {
    // TODO: implement settleSolanaPayment
}

export { settleExactPayment, settlePermitPayment, settleSolanaPayment }