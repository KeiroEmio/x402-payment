import { Request, Response, NextFunction } from "express";
import { logger } from "./logger";
import { decodeXPaymentResponse } from "x402-axios";
import {
    Network,
    PaymentPayload,
    PaymentRequirements,
    Price,
    Resource,
    settleResponseHeader,
    // x402Response,
} from "x402/types"
import { exact } from "x402/schemes";
import { processPriceToAtomicAmount, findMatchingPaymentRequirements } from "x402/shared";
import { masterSetup } from './util'
import { inspect } from 'node:util'
import { ethers, Wallet } from 'ethers'
import { facilitator, createFacilitatorConfig } from "@coinbase/x402"
import { useFacilitator } from "x402/verify"
import { ReflashData, x402paymentHeader, x402SettleResponse, payload, airDrop, facilitatorsPoolType, x402Response } from './types'
import Settle_ABI from './ABI/sellte-abi.json'
import USDC_ABI from './ABI/usdc_abi.json'

const x402Version: number = 1;
const facilitator1 = createFacilitatorConfig(masterSetup.base.CDP_API_KEY_ID, masterSetup.base.CDP_API_KEY_SECRET)
const { verify, settle } = useFacilitator(facilitator1)
// base-speolia
const USDCContract = '0x036CbD53842c5426634e7929541eC2318f3dCF7e'

const SETTLEContract = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'

// Offline signature transfer address are defined by the server.
const tagetAddress = '0xe11B1025F25124550E148072a14590D43Fb79625'
// const eventContract = '0x18A976ee42A89025f0d3c7Fb8B32e0f8B840E1F3'

const MINT_RATE = ethers.parseUnits('7000', 18)
const facilitatorsPool: facilitatorsPoolType[] = []
const x402ProcessPool: airDrop[] = []
// const eventProvider = new ethers.JsonRpcProvider(masterSetup.base_endpoint)
const baseProvider = new ethers.JsonRpcProvider(masterSetup.base_endpoint)
const ReflashData: ReflashData[] = []
const Settle_ContractPool = masterSetup.settle_contractAdmin.map((n: string) => {
    const admin = new ethers.Wallet(n, baseProvider)
    // const adminEvent = new ethers.Wallet(n, eventProvider)
    logger(`address ${admin.address} added to Settle_ContractPool`)
    return {
        base: new ethers.Contract(SETTLEContract, Settle_ABI, admin),
        // event: new ethers.Contract(eventContract, Event_ABI, adminEvent),
        usdc: new ethers.Contract(USDCContract, USDC_ABI, admin)
    }
})

export async function verifyPayment(
    req: Request,
    res: Response,
    paymentRequirements: PaymentRequirements[],
    x402Version: number,
): Promise<boolean> {
    const payment = req.header("X-PAYMENT");
    if (!payment) {
        res.status(402).json({
            x402Version,
            error: "X-PAYMENT header is required",
            accepts: paymentRequirements,
        });
        return false;
    }

    //verify paymentRequirements with exact.evm.decodePayment(req.header("X-PAYMENT"))
    let decodedPayment: PaymentPayload;
    try {
        decodedPayment = exact.evm.decodePayment(payment);
        decodedPayment.x402Version = x402Version;
    } catch (error) {
        res.status(402).json({
            x402Version,
            error: error || "Invalid or malformed payment header",
            accepts: paymentRequirements,
        });
        return false;
    }

    try {
        const selectedPaymentRequirement =
            findMatchingPaymentRequirements(paymentRequirements, decodedPayment) ||
            paymentRequirements[0];

        const response = await verify(decodedPayment, selectedPaymentRequirement)

        if (!response.isValid) {
            // 📌 verify false
            res.status(402).json({
                x402Version,
                error: response.invalidReason,
                accepts: paymentRequirements,
                payer: response.payer,
            })
            return false
        }
    } catch (error) {
        res.status(402).json({
            x402Version,
            error,
            accepts: paymentRequirements,
        });
        return false
    }

    return true
}

export const checkx402paymentHeader = (paymentHeader: x402paymentHeader, amount: number) => {
    if (paymentHeader?.payload?.authorization?.to?.toLowerCase() !== SETTLEContract.toLowerCase()) {
        return false
    }
    const _payAmount = paymentHeader?.payload?.authorization?.value
    if (!_payAmount) {
        return false
    }

    const payAmount = parseFloat(_payAmount)
    if (isNaN(payAmount) || payAmount < amount) {
        return false
    }

    return true
}

export const processPayment = async (req: any, res: any, price: string) => {
    const _routerName = req.path

    const resource = `${req.protocol}://${req.headers.host}${req.originalUrl}` as Resource
    const USDC_tokenValue = ethers.parseUnits(price, 6)
    const SETTLE_tokenvalue = USDC_tokenValue * MINT_RATE
    const SETTLE_token_ether = ethers.formatEther(SETTLE_tokenvalue)

    const paymentRequirements = [createExactPaymentRequirements(
        price,
        resource,
        `SETTLE Mint / Early Access $SETTLE ${SETTLE_token_ether}`
    )];

    const isValid = await verifyPayment(req, res, paymentRequirements, x402Version)

    if (!isValid) {
        return
    }

    let x402SettleResponse: x402SettleResponse

    const paymentHeader = exact.evm.decodePayment(req.header("X-PAYMENT")!)
    const saleRequirements = paymentRequirements[0]
    const isValidPaymentHeader = checkx402paymentHeader(paymentHeader as x402paymentHeader, 1000)

    if (!isValidPaymentHeader) {
        logger(`${_routerName} checkx402paymentHeader Error!`, inspect(paymentHeader))
        return res.status(402).end()
    }

    try {
        const settleResponse = await settle(
            paymentHeader,
            saleRequirements
        )

        const responseHeader = settleResponseHeader(settleResponse)

        // In a real application, you would store this response header
        // and associate it with the payment for later verification

        x402SettleResponse = JSON.parse(Buffer.from(responseHeader, 'base64').toString())

        if (!x402SettleResponse.success) {
            logger(`${_routerName} responseData ERROR!`, inspect(x402SettleResponse, false, 3, true))
            return res.status(402).end()
        }
        res.setHeader('X-PAYMENT-RESPONSE', responseHeader)
    } catch (error) {
        console.error("Payment settlement failed:", error);

        // In a real application, you would handle the failed payment
        // by marking it for retry or notifying the user
        // const payload: payload = paymentHeader?.payload as payload
        // if (payload?.authorization) {
        //     facilitatorsPool.push({
        //         from: payload.authorization.from,
        //         value: payload.authorization.value,
        //         validAfter: payload.authorization.validAfter,
        //         validBefore: payload.authorization.validBefore,
        //         nonce: payload.authorization.nonce,
        //         signature: payload.signature,
        //         res: res
        //     })
        //     // return processPaymebnt(req, res, price)
        //     return facilitators()
        // }

        // logger(inspect({ paymentHeader, saleRequirements }, false, 3, true))

        return res.status(402).end()
    }
    const wallet = x402SettleResponse.payer

    const isWallet = ethers.isAddress(wallet)

    const ret: x402Response = {
        success: true,
        payer: wallet,
        USDC_tx: x402SettleResponse?.transaction,
        network: x402SettleResponse?.network,
        timestamp: new Date().toISOString()
    }

    if (isWallet) {
        x402ProcessPool.push({
            wallet,
            settle: ethers.parseUnits('0.001', 6).toString()
        })

        logger(`${_routerName} success!`, inspect(x402SettleResponse, false, 3, true))
        process_x402()
    }

    res.status(200).json(ret).end()
}

function createExactPaymentRequirements(
    price: Price,
    resource: Resource,
    description: string,
): PaymentRequirements {
    const atomicAmountForAsset = processPriceToAtomicAmount(price, 'base-sepolia')
    if ("error" in atomicAmountForAsset) {
        throw new Error(atomicAmountForAsset.error);
    }
    const { maxAmountRequired, asset } = atomicAmountForAsset;

    return {
        scheme: "exact",
        network: 'base-sepolia',
        maxAmountRequired,
        resource,
        description,
        mimeType: "application/json",
        payTo: tagetAddress,
        maxTimeoutSeconds: 10,
        asset: asset.address,
        outputSchema: undefined,
        extra: {
            name: 'USDC',
            version: '2',
        },
        // extra: { "gasLimit": "1000000" }
    };
}

const process_x402 = async () => {
    const obj = x402ProcessPool.shift()
    if (!obj) {
        return
    }

    const SC = Settle_ContractPool.shift()
    if (!SC) {
        logger(`process_x402 got empty Settle_testnet_pool`)
        x402ProcessPool.unshift(obj)
        return
    }

    try {
        //impl a transcation will get SETTLE token
        const tx = await SC.base.mint(
            obj.wallet, obj.settle
        )

        await tx.wait()
        const USDC_decimals = BigInt(10 ** 6)
        const SETTLE = BigInt(obj.settle) * MINT_RATE / USDC_decimals

        // const ts = await SC.event.eventEmit(
        //     obj.wallet, obj.settle, SETTLE, tx.hash
        // )
        // await ts.wait()
        // console.log(`ts: ${tx.hash}`)
        console.log(`SETTLE: ${SETTLE.toString()}`)
        ReflashData.unshift({
            wallet: obj.wallet,
            hash: tx.hash,
            USDC: obj.settle,
            timestmp: new Date().toUTCString(),
            SETTLE: SETTLE.toString(),
        })

        logger(`process_x402 success: ${tx.hash}`)

    } catch (ex: any) {
        logger(`Error process_x402 `, ex.message)
        x402ProcessPool.unshift(obj)
    }

    Settle_ContractPool.push(SC)
    setTimeout(() => process_x402(), 1000)
}



