import express from 'express'
import type { Server } from 'node:http'
import { request } from 'node:https'
import type { RequestOptions } from 'node:https'
import { join, resolve } from 'node:path'
import Colors from 'colors/safe'
import { inspect } from 'node:util'
import { logger } from './logger'

import { ethers, Wallet } from 'ethers'
import os from 'node:os'
import fs from 'node:fs'
import { useFacilitator } from "x402/verify"
import { masterSetup } from './util'
import Settle_ABI from './ABI/sellte-abi.json'
import Event_ABI from './ABI/event-abi.json'
import USDC_ABI from './ABI/usdc_abi.json'
import { facilitator, createFacilitatorConfig } from "@coinbase/x402"
import { exact } from "x402/schemes";
import {
	Network,
	PaymentPayload,
	PaymentRequirements,
	Price,
	Resource,
	settleResponseHeader,
	// x402Response,
} from "x402/types"
import { processPriceToAtomicAmount, findMatchingPaymentRequirements } from "x402/shared";
import { ReflashData, x402paymentHeader, x402SettleResponse, payload, airDrop, facilitatorsPoolType, x402Response } from './types'

const facilitator1 = createFacilitatorConfig(masterSetup.base.CDP_API_KEY_ID, masterSetup.base.CDP_API_KEY_SECRET)
const { verify, settle } = useFacilitator(facilitator1)

// base-speolia
const USDCContract = '0x036CbD53842c5426634e7929541eC2318f3dCF7e'

const SETTLEContract = '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913'

const eventContract = '0x18A976ee42A89025f0d3c7Fb8B32e0f8B840E1F3'

const baseProvider = new ethers.JsonRpcProvider(masterSetup.base_endpoint)
// const eventProvider = new ethers.JsonRpcProvider('https://mainnet-rpc.conet.network')
const eventProvider = new ethers.JsonRpcProvider(masterSetup.base_endpoint)
const Settle_ContractPool = masterSetup.settle_contractAdmin.map((n: string) => {
	const admin = new ethers.Wallet(n, baseProvider)
	const adminEvent = new ethers.Wallet(n, eventProvider)
	logger(`address ${admin.address} added to Settle_ContractPool`)
	return {
		base: new ethers.Contract(SETTLEContract, Settle_ABI, admin),
		event: new ethers.Contract(eventContract, Event_ABI, adminEvent),
		usdc: new ethers.Contract(USDCContract, USDC_ABI, admin)
	}
})

const x402Version = 1

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
		payTo: SETTLEContract,
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

const checkSig = (ercObj: any): {
	v: number
	r: string
	s: string
	recoveredAddress: string
	isValid: boolean
} | null => {
	try {
		if (!ercObj || !ercObj.sig || !ercObj.EIP712) {
			console.log('❌ Invalid ercObj: missing sig or EIP712')
			return null
		}

		const sigRaw: string = ercObj.sig
		const eip712: any = ercObj.EIP712
		const message: any = eip712?.message || {}

		const now = Math.floor(Date.now() / 1000)
		const validAfter = BigInt((message?.validAfter ?? 0).toString())
		const validBefore = BigInt((message?.validBefore ?? 0).toString())
		if (now < Number(validAfter)) {
			console.log(`❌ Signature not yet valid: now=${now}, validAfter=${validAfter}`)
			return null
		}
		if (now > Number(validBefore)) {
			console.log(`❌ Signature expired: now=${now}, validBefore=${validBefore}`)
			return null
		}
		const domain = {
			name: eip712?.domain?.name,
			version: eip712?.domain?.version,
			chainId:
				typeof eip712?.domain?.chainId === 'string'
					? Number(eip712.domain.chainId)
					: eip712?.domain?.chainId,
			verifyingContract: eip712?.domain?.verifyingContract
		}

		// 规范化 types：可能是对象，也可能被序列化为字符串
		const typesObj: Record<string, Array<{ name: string; type: string }>> =
			typeof eip712?.types === 'string'
				? JSON.parse(eip712.types)
				: (eip712?.types as any)

		if (!typesObj || typeof typesObj !== 'object') {
			console.log('❌ EIP712.types is not a valid object')
			return null
		}

		// —— First choice: verifyTypedData (highest content is incorrect) ——
		try {
			const recovered = ethers.verifyTypedData(domain as any, typesObj as any, message, sigRaw)
			const isValid = recovered?.toLowerCase?.() === message?.from?.toLowerCase?.()
			if (isValid) {
				// Split v/r/s for use on subsequent chains
				const normalizedSig = sigRaw.startsWith('0x') ? sigRaw : ('0x' + sigRaw)
				const sig = ethers.Signature.from(normalizedSig)
				// v Normalized to 27/28 (some wallets return 0/1)

				let v: number = Number(sig.v)
				if (v === 0 || v === 1) v += 27

				console.log(`✅ verifyTypedData OK. recovered=${recovered}`)
				return {
					v,
					r: sig.r,
					s: sig.s,
					recoveredAddress: recovered,
					isValid: true
				}
			} else {
				console.log(`⚠️ verifyTypedData recovered=${recovered}, expected=${message?.from}`)
			}
		} catch (e: any) {
			console.log(`⚠️ verifyTypedData failed: ${e?.message || String(e)}`)
		}

		// —— fallback：手工 hash + recoverAddress ——

		// 1)  v/r/s
		let hex = sigRaw.startsWith('0x') ? sigRaw : ('0x' + sigRaw)
		if (hex.length !== 132) {
			console.log(`⚠️ Unusual signature length=${hex.length}, still attempting recovery`)
		}
		const r = '0x' + hex.slice(2, 66)
		const s = '0x' + hex.slice(66, 130)
		let v = parseInt(hex.slice(130, 132) || '1b', 16)
		if (v === 0 || v === 1) v += 27
		if (v !== 27 && v !== 28) console.log(`⚠️ Unusual v=${v} after normalization`)

		const msgForHash: any = {
			from: message.from,
			to: message.to,
			value: BigInt(message.value?.toString?.() ?? message.value ?? 0),
			validAfter: BigInt(message.validAfter?.toString?.() ?? message.validAfter ?? 0),
			validBefore: BigInt(message.validBefore?.toString?.() ?? message.validBefore ?? 0),
			nonce: message.nonce
		}

		let digest: string
		try {
			digest = ethers.TypedDataEncoder.hash(domain as any, typesObj as any, msgForHash)
			console.log(`📋 digest=${digest}`)
		} catch (e: any) {
			console.log(`❌ TypedDataEncoder.hash error: ${e?.message || String(e)}`)
			return null
		}

		// 4) recover address
		let recoveredAddress: string
		try {
			recoveredAddress = ethers.recoverAddress(digest, { v, r, s })
			console.log(`✅ fallback recovered=${recoveredAddress}`)
		} catch (e: any) {
			console.log(`❌ recoverAddress error: ${e?.message || String(e)}`)
			return null
		}

		const isValid = recoveredAddress?.toLowerCase?.() === message?.from?.toLowerCase?.()
		if (!isValid) {
			console.log(`❌ INVALID signature. expected=${message?.from}, got=${recoveredAddress}`)
		}

		return { v, r, s, recoveredAddress, isValid }
	} catch (err: any) {
		console.log(`❌ checkSig fatal error: ${err?.message || String(err)}`)
		return null
	}
}

const initialize = async (reactBuildFolder: string, PORT: number, setupRoutes: (router: any) => void) => {
	console.log('🔧 Initialize called with PORT:', PORT, 'reactBuildFolder:', reactBuildFolder)


	const defaultPath = join(__dirname, 'workers')
	console.log('📁 defaultPath:', defaultPath)

	const userDataPath = reactBuildFolder
	const updatedPath = join(userDataPath, 'workers')
	console.log('📁 updatedPath:', updatedPath)

	let staticFolder = fs.existsSync(updatedPath) ? updatedPath : defaultPath
	logger(`staticFolder = ${staticFolder}`)
	console.log('📁 staticFolder:', staticFolder)
	const isProd = process.env.NODE_ENV === "production";

	const app = express()
	app.set("trust proxy", true);
	if (!isProd) {
		app.use((req, res, next) => {
			res.setHeader('Access-Control-Allow-Origin', '*');
			res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
			res.setHeader(
				'Access-Control-Allow-Headers',
				'Content-Type, Authorization, X-Requested-With, X-PAYMENT, Access-Control-Expose-Headers'
			);
			res.setHeader('Access-Control-Expose-Headers', 'Content-Length, Content-Range, X-PAYMENT-RESPONSE');
			if (req.method === 'OPTIONS') return res.sendStatus(204);
			next();
		});
	} else {
		app.use((req, _res, next) => {
			if (!req.get('x-forwarded-proto')) {
				req.headers['x-forwarded-proto'] = 'https';
			}
			next();
		});
	}
	// app.use ( express.static ( staticFolder ))
	app.use(express.json())

	app.use(async (req, res: any, next) => {
		logger(Colors.blue(`${req.url}`))
		return next()
	})

	const cors = require('cors')

	if (!isProd) {
		app.use(/.*/, cors({
			origin: ['http://localhost:4088'],
			methods: ['GET', 'POST', 'OPTIONS'],
			allowedHeaders: [
				'Content-Type',
				'Authorization',
				'X-Requested-With',
				'X-PAYMENT',
				'Access-Control-Expose-Headers',
			],
			exposedHeaders: ['X-PAYMENT-RESPONSE'],
			credentials: false,
			optionsSuccessStatus: 204,
			maxAge: 600,
		}));
	}

	const router = express.Router()

	app.use('/api', router)
	setupRoutes(router)

	logger('Router stack:', router.stack.map(r => r.route?.path))

	app.get('/_debug', (req, res) => {
		res.json({
			protocol: req.protocol,
			secure: req.secure,
			host: req.get('host'),
			xfp: req.get('x-forwarded-proto'),
		});
	});

	app.once('error', (err: any) => {
		logger(err)
		logger(`Local server on ERROR, try restart!`)
		return
	})

	app.all('/', (req: any, res: any) => {
		return res.status(404).end()
	})

	const server = app.listen(PORT, () => {
		console.log('✅ Server started successfully!')
		console.table([
			{ 'x402 Server': `http://localhost:${PORT}`, 'Serving files from': staticFolder }
		])
	})

	server.on('error', (err: any) => {
		console.error('❌ Server error:', err)
	})

	return server
}

async function verifyPayment(
	req: express.Request,
	res: express.Response,
	paymentRequirements: PaymentRequirements[],
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



const checkx402paymentHeader = (paymentHeader: x402paymentHeader, amount: number) => {
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



const processPaymebnt = async (req: any, res: any, price: string) => {
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

	const isValid = await verifyPayment(req, res, paymentRequirements)

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
		const payload: payload = paymentHeader?.payload as payload
		if (payload?.authorization) {
			facilitatorsPool.push({
				from: payload.authorization.from,
				value: payload.authorization.value,
				validAfter: payload.authorization.validAfter,
				validBefore: payload.authorization.validBefore,
				nonce: payload.authorization.nonce,
				signature: payload.signature,
				res: res
			})
			// return processPaymebnt(req, res, price)
			return facilitators()
		}

		logger(inspect({ paymentHeader, saleRequirements }, false, 3, true))

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

const facilitatorsPool: facilitatorsPoolType[] = []

const facilitators = async () => {
	const obj = facilitatorsPool.shift()
	if (!obj) {
		return
	}

	const SC = Settle_ContractPool.shift()
	if (!SC) {
		facilitatorsPool.unshift(obj)
		return setTimeout(() => facilitators(), 1000)
	}
	const wallet = obj.from

	try {
		const tx = await SC.usdc.transferWithAuthorization(
			obj.from, SETTLEContract, obj.value, obj.validAfter, obj.validBefore, obj.nonce, obj.signature
		)
		await tx.wait()
		logger(`facilitators success! ${tx.hash}`)

		const ret: x402Response = {
			success: true,
			payer: wallet,
			USDC_tx: tx.hash,
			network: 'BASE',
			timestamp: new Date().toISOString()
		}

		obj.res.status(200).json(ret).end()
		Settle_ContractPool.push(SC)

		x402ProcessPool.push({
			wallet,
			settle: ethers.parseUnits('0.001', 6).toString()
		})

		await process_x402()
		return setTimeout(() => facilitators(), 1000)

	} catch (ex: any) {
		logger(`facilitators Error!`, ex.message)
	}

	//	transferWithAuthorization

	Settle_ContractPool.push(SC)
	setTimeout(() => facilitators(), 1000)
}


const router = (router: express.Router) => {
	router.get('/weather', async (req, res) => {
		processPaymebnt(req, res, '0.001')
		//demo resource
		const weatherData = {
			temperature: 25,
			condition: '晴天',
			city: 'HangZhou',
			paid: true,
		}
		return res.status(200).json({ success: true, data: weatherData });
	})

	router.get('/settleHistory', async (req, res) => {
		res.status(200).json(ReflashData.slice(0, 20)).end()
	})

	router.get('/settle0001', async (req, res) => {
		return processPaymebnt(req, res, '0.001')
	})
	//	https://api.settleonbase.xyz/api/settle001
	router.get('/settle001', async (req, res) => {
		return processPaymebnt(req, res, '0.01')
	})

	router.get('/settle01', async (req, res) => {

		return processPaymebnt(req, res, '0.1')

	})

	router.get('/settle1', async (req, res) => {
		return processPaymebnt(req, res, '1.00')

	})

	router.get('/settle10', async (req, res) => {
		return processPaymebnt(req, res, '10.00')

	})

	router.get('/settle100', async (req, res) => {
		return processPaymebnt(req, res, '100.00')

	})
}
const x402ProcessPool: airDrop[] = []

const MINT_RATE = ethers.parseUnits('7000', 18)
const USDC_decimals = BigInt(10 ** 6)


const SETTLE_FILE = join(os.homedir(), "settle.json")

// 已持久化的 hash 集
const persistedHashes = new Set<string>()

// 文件中现有的所有记录（倒序，最新在前）
let fileCache: ReflashData[] = []

// 定时器句柄
let settleFlushTimer: NodeJS.Timeout | null = null;
let flushing = false;



async function flushNewReflashData(): Promise<void> {
	if (flushing) return;
	flushing = true;
	try {
		// 仅挑出 reflashData 中“尚未写入文件”的新项（靠 hash 去重）
		const newOnes: ReflashData[] = [];
		for (const r of ReflashData) {
			if (!persistedHashes.has(r.hash)) {
				newOnes.push(r);
			} else {
				// r.hash 已经入库，说明其后的老记录很可能也已入库，
				// 但不做提前 break，允许 reflashData 前 20 之外的新增也被补齐。
			}
		}

		if (newOnes.length === 0) return;

		await loadSettleFile();

		const reallyNew = newOnes.filter(r => !persistedHashes.has(r.hash));
		if (reallyNew.length === 0) return;

		const nextFile = [...reallyNew, ...fileCache];

		const tmp = SETTLE_FILE + ".tmp";
		await fs.writeFileSync(tmp, JSON.stringify(nextFile, null, 2), "utf8")
		await fs.renameSync(tmp, SETTLE_FILE)

		fileCache = nextFile;
		for (const r of reallyNew) persistedHashes.add(r.hash);
	} catch (e: any) {
		console.error("[settle.json] flush error:", e?.message || e);
	} finally {
		flushing = false;
	}
}




const process_x402 = async () => {
	console.debug(`process_x402`)
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
		const tx = await SC.base.mint(
			obj.wallet, obj.settle
		)

		await tx.wait()

		const SETTLE = BigInt(obj.settle) * MINT_RATE / USDC_decimals



		const ts = await SC.event.eventEmit(
			obj.wallet, obj.settle, SETTLE, tx.hash
		)
		await ts.wait()

		ReflashData.unshift({
			wallet: obj.wallet,
			hash: tx.hash,
			USDC: obj.settle,
			timestmp: new Date().toUTCString(),
			SETTLE: SETTLE.toString(),
		})

		logger(`process_x402 success! ${tx.hash}`)

	} catch (ex: any) {
		logger(`Error process_x402 `, ex.message)
		x402ProcessPool.unshift(obj)
	}

	Settle_ContractPool.push(SC)
	setTimeout(() => process_x402(), 1000)

}


const ReflashData: ReflashData[] = []
const loadSettleFile = async () => {
	try {
		const buf = await fs.readFileSync(SETTLE_FILE, 'utf8');
		const arr = JSON.parse(buf);

		if (Array.isArray(arr)) {
			logger(`loadSettleFile ${SETTLE_FILE}`, inspect(arr, false, 3, true));

			// ✅ 先去重（按 tx 或 hash 唯一）
			const uniqueMap = new Map<string, ReflashData>();

			for (const item of arr as ReflashData[]) {
				const key = item.hash || item.hash || JSON.stringify(item); // 兜底
				if (!uniqueMap.has(key)) uniqueMap.set(key, item);
			}
			let deduped = Array.from(uniqueMap.values());



			// ✅ 保存至缓存（保证最新在前）
			fileCache = deduped;

		} else {
			fileCache = [];
			logger(`loadSettleFile ${SETTLE_FILE} Empty array`);
		}
	} catch (e: any) {
		logger(`loadSettleFile ${SETTLE_FILE} ERROR!`);
		if (e?.code === "ENOENT") {
			fileCache = [];
			await fs.writeFileSync(SETTLE_FILE, "[]", 'utf8');
		} else {
			console.error(`[settle.json] ${SETTLE_FILE} read error: `, e?.message || e);
			fileCache = [];
		}
	}

	// ✅ 初始化 ReflashData 数组（最多前 20 条，倒序）
	ReflashData.splice(0, ReflashData.length, ...fileCache.slice(0, 20));
	logger(`ReflashData initialized with ${ReflashData.length} items`);
};

async function initSettlePersistence() {
	await loadSettleFile();

	// 每 5 分钟增量落盘
	settleFlushTimer = setInterval(flushNewReflashData, 5 * 60 * 1000);

	// 进程退出时兜底 flush 一次
	const onExit = async () => {
		try {
			if (settleFlushTimer) clearInterval(settleFlushTimer);
			await flushNewReflashData();
		} catch { }
		process.exit(0);
	}

	process.on("SIGINT", onExit);
	process.on("SIGTERM", onExit);
	process.on("beforeExit", async () => {
		await flushNewReflashData();
	})
}
export class x402Server {

	private loginListening: express.Response | null = null
	private localserver: Server | null = null
	private connect_peer_pool: any[] = []
	private worker_command_waiting_pool: Map<string, express.Response> = new Map()
	private logStram: any

	constructor(private PORT = 3000, private reactBuildFolder: string) {
		this.logStram =
			console.log('🗑️  x402Server constructor called')
	}

	public async start(): Promise<void> {
		console.log('⏳ start() called')
		try {
			this.localserver = await initialize(this.reactBuildFolder, this.PORT, router)
			console.log('✨ start() completed successfully')
		} catch (err) {
			console.error('❌ start() error:', err)
			throw err
		}
	}

	public end = (): Promise<void> => new Promise(resolve => {
		if (this.localserver) {
			this.localserver.close(err => {
				if (err) {
					logger(Colors.red('Server err:'), err)
				}
			})
		}
		resolve()
	})



	public postMessageToLocalDevice(device: string, encryptedMessage: string) {
		const index = this.connect_peer_pool.findIndex(n => n.publicKeyID === device)
		if (index < 0) {
			return console.log(inspect({ postMessageToLocalDeviceError: `this.connect_peer_pool have no publicKeyID [${device}]` }, false, 3, true))
		}
		const ws = this.connect_peer_pool[index]
		const sendData = { encryptedMessage: encryptedMessage }
		console.log(inspect({ ws_send: sendData }, false, 3, true))
		return ws.send(JSON.stringify(sendData))
	}
}


const logPath = join(os.homedir(), "esttleEvent.json")


let newRecords1: any = []

function flushNow() {
	if (newRecords1.length === 0) return
	if (flushing) return                   // 简单并发保护
	flushing = true
	try {
		let oldArr = []
		if (fs.existsSync(logPath)) {
			const raw = fs.readFileSync(logPath, "utf8")
			const parsed = JSON.parse(raw)
			oldArr = Array.isArray(parsed) ? parsed : []
		}

		newRecords1.sort((a: any, b: any) => (b.blockNumber ?? 0) - (a.blockNumber ?? 0))

		const merged = [...newRecords1, ...oldArr]

		fs.writeFileSync(logPath, JSON.stringify(merged, null, 2))
		console.log(`[SETTLE] flush: wrote ${newRecords1.length} new records to ${logPath}`)
		newRecords1 = []
	} catch (e) {
		console.error("[SETTLE] flush failed:", e)
	} finally {
		flushing = false
	}
}

console.log('📌 Script started')
export function flushNowAndExit() {
	try { flushNow() } finally { process.exit(0) }
}




(async () => {
	try {
		console.log('🌐 Creating x402Server instance...')
		const server = new x402Server(4088, '')
		initSettlePersistence()
		console.log('⏳ Calling server.start()...')
		// listenEvent()
		await server.start()

		console.log('✅ Server started successfully!')


		process.on('SIGINT', async () => {
			logger('Shutting down gracefully...')
			await server.end()
			process.exit(0)
		})

		console.log('🎯 Server is now running. Press Ctrl+C to exit.')

	} catch (error) {
		logger(Colors.red('Failed to start server:'), error)
		console.error('❌ Error details:', error)
		process.exit(1)
	}
})()


console.log('📌 Script setup completed')
