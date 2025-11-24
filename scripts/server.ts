import express from 'express'
import type { Server } from 'node:http'
import { join, resolve } from 'node:path'
import Colors from 'colors/safe'
import { inspect } from 'node:util'
import { logger } from './logger'

import { ethers, Wallet } from 'ethers'
import os from 'node:os'
import fs from 'node:fs'

import { processPayment } from './verify'
import { ReflashData } from './types'

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
	logger('🔧 Initialize called with PORT:', PORT, 'reactBuildFolder:', reactBuildFolder)

	const defaultPath = join(__dirname, 'workers')

	const updatedPath = join(reactBuildFolder, 'workers')

	let staticFolder = fs.existsSync(updatedPath) ? updatedPath : defaultPath
	logger(`staticFolder = ${staticFolder}`)

	const isProd = process.env.NODE_ENV === "production";

	const app = express()
	// app.set("trust proxy", true);  reality real ip to user.
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
		logger(Colors.yellow(`${req.url}`))
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

const router = (router: express.Router) => {
	router.get('/weather', async (req, res) => {
		return processPayment(req, res, '0.001')
	})

	router.get('/settleHistory', async (req, res) => {
		res.status(200).json(ReflashData.slice(0, 20)).end()
	})

	router.get('/settle0001', async (req, res) => {
		return processPayment(req, res, '0.001')
	})
	//	https://api.settleonbase.xyz/api/settle001
	router.get('/settle001', async (req, res) => {
		return processPayment(req, res, '0.01')
	})

	router.get('/settle01', async (req, res) => {

		return processPayment(req, res, '0.1')

	})

	router.get('/settle1', async (req, res) => {
		return processPayment(req, res, '1.00')

	})

	router.get('/settle10', async (req, res) => {
		return processPayment(req, res, '10.00')

	})

	router.get('/settle100', async (req, res) => {
		return processPayment(req, res, '100.00')

	})
}

const SETTLE_FILE = join(os.homedir(), "settle.json")

// persistent hash set
const persistedHashes = new Set<string>()

let fileCache: ReflashData[] = []

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

const ReflashData: ReflashData[] = []
const loadSettleFile = async () => {
	try {
		const buf = await fs.readFileSync(SETTLE_FILE, 'utf8');
		const arr = JSON.parse(buf);

		if (Array.isArray(arr)) {
			logger(`loadSettleFile ${SETTLE_FILE}`, inspect(arr, false, 3, true));

			const uniqueMap = new Map<string, ReflashData>();

			for (const item of arr as ReflashData[]) {
				const key = item.hash || item.hash || JSON.stringify(item);
				if (!uniqueMap.has(key)) uniqueMap.set(key, item);
			}
			let deduped = Array.from(uniqueMap.values());

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
	ReflashData.splice(0, ReflashData.length, ...fileCache.slice(0, 20));
	logger(`ReflashData initialized with ${ReflashData.length} items`);
};

async function initSettlePersistence() {
	await loadSettleFile();

	settleFlushTimer = setInterval(flushNewReflashData, 5 * 60 * 1000);

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
	if (flushing) return
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
