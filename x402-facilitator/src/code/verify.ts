
import { PaymentPayload, PaymentRequirement, VerifyResponse } from '../types/PaymentRequired';
import { ethers } from 'ethers';
import { ERC20AssetMap, Domain } from '../types/type';
import { X402_VERSIONS } from '../types/version';
import { Scheme } from '../types/type';

export async function verifyExactPayment(
    payload: PaymentPayload,
    requirement: PaymentRequirement,
    provider: ethers.Provider
): Promise<VerifyResponse> {
    let domain: Domain;
    if (!("signature" in payload.payload) || !("authorization" in payload.payload)) {
        return { x402Version: X402_VERSIONS[0], isValid: false, error: "invalid_payload" };
    }

    const { signature, authorization } = payload.payload;

    if (
        authorization.to.toLowerCase() !== requirement.payTo.toLowerCase() ||
        BigInt(authorization.value) > requirement.maxAmountRequired
    ) {
        return { x402Version: X402_VERSIONS[0], isValid: false, error: "x402 exact requirement_mismatch" };
    }

    const now = Math.floor(Date.now() / 1000);
    if (now < Number(authorization.validAfter) || now >= Number(authorization.validBefore)) {
        return { x402Version: X402_VERSIONS[0], isValid: false, error: "expired" };
    }

    const token = new ethers.Contract(
        requirement.asset,
        ["function authorizationState(address authorizer, bytes32 nonce) view returns (bool)"],
        provider
    );
    const nonce32 = ethers.zeroPadValue(authorization.nonce, 32);
    if (await token.authorizationState(authorization.from, nonce32)) {
        return { x402Version: X402_VERSIONS[0], isValid: false, error: "verify nonce_used" };
    }

    //signature recovery（EIP-3009）
    const chainId = (await provider.getNetwork()).chainId;

    if (!requirement.extra) {
        domain = {
            name: ERC20AssetMap[payload.network].eip712.name,
            version: ERC20AssetMap[payload.network].eip712.version,
            chainId: Number(chainId),
            verifyingContract: requirement.asset,
        };
    } else {
        domain = {
            name: requirement.extra.name,
            version: requirement.extra.version,
            chainId: Number(chainId),
            verifyingContract: requirement.asset,
        };
    }

    const value = {
        from: authorization.from,
        to: authorization.to,
        value: authorization.value,
        validAfter: authorization.validAfter,
        validBefore: authorization.validBefore,
        nonce: nonce32,
    };

    const recovered = ethers.verifyTypedData(
        domain,
        {
            TransferWithAuthorization: [
                { name: "from", type: "address" },
                { name: "to", type: "address" },
                { name: "value", type: "uint256" },
                { name: "validAfter", type: "uint256" },
                { name: "validBefore", type: "uint256" },
                { name: "nonce", type: "bytes32" },
            ],
        },
        value,
        signature
    );

    if (recovered.toLowerCase() !== authorization.from.toLowerCase()) {
        return { x402Version: X402_VERSIONS[0], isValid: false, error: "verify error,invalid_signature" };
    }

    return {
        x402Version: X402_VERSIONS[0],
        isValid: true,
        payer: authorization.from,
        accepts: [{
            scheme: Scheme.Exact,
            description: requirement.description,
            asset: requirement.asset,
            maxAmountRequired: requirement.maxAmountRequired.toString(),
            network: payload.network,
            resource: requirement.resource,
            mimeType: requirement.mimeType,
            payTo: requirement.payTo,
            maxTimeoutSeconds: requirement.maxTimeoutSeconds,
            outputSchema: requirement.outputSchema,
            extra: requirement.extra,
        }],
    };
}

export function verifyPermitPayment(decodePayment: PaymentPayload, selectedRequirement: PaymentRequirement): VerifyResponse {
    //...
    return {
        x402Version: X402_VERSIONS[0],
        isValid: true,
    }
}

export function verifySolanaPayment(decodePayment: PaymentPayload, selectedRequirement: PaymentRequirement): VerifyResponse {
    //...
    return {
        x402Version: X402_VERSIONS[0],
        isValid: true,
    }
}