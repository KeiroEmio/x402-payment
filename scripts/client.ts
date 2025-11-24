import { config as dotenvConfig } from 'dotenv'
import { resolve } from 'path'
import axios from 'axios'
import { withPaymentInterceptor, decodeXPaymentResponse, createSigner, type Hex } from "x402-axios";
dotenvConfig({ path: resolve(__dirname, '../.env') })

// let input: any;
const pk = process.env.PAYER_PK as Hex | string
if (!pk) {
    throw new Error('not set PAYER_PK: ' + pk)
}
const baseURL = "http://localhost:4088" as string;
// const endpointPath = "/api/weather" as string;
const endpointPath = "/api/weather" as string;

// Assemble and sign EIP-712 data
async function signExactPayload() {
    try {
        const signer = await createSigner("base-sepolia", "0x" + pk);
        const api = withPaymentInterceptor(
            axios.create({
                baseURL,
            }),
            signer,
        );
        // call first req to return paymentRequired , and then sign it , send second req for endpointPath.
        const response = await api.get(endpointPath);
        console.log(response.data);

        const paymentResponse = decodeXPaymentResponse(response.headers["x-payment-response"]);
        console.log("x-payment-response", paymentResponse)
    } catch (error) {
        console.error('signExactPayload error:', error)
    }
}

signExactPayload().catch(err => {
    // console.error('signExactPayload error:', err)
    process.exit(1)
})

//npx ts-node src/client.ts