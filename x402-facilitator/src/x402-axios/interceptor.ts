import type { AxiosInstance } from 'axios';
import type { ISigner } from './types';
import { PaymentRequirement } from '../types/PaymentRequired';

export function withPaymentInterceptor(
    axiosInstance: AxiosInstance,
    signer: ISigner,
): AxiosInstance {
    axiosInstance.interceptors.response.use(
        (response) => response,
        async (error) => {
            const res = error.response;
            if (res?.status === 402 && res.headers['x-payment-required']) {
                try {
                    const paymentRequired = JSON.parse(res.headers['x-payment-required']) as PaymentRequirement;
                    const signedPayload = await signer.offSignTransaction(paymentRequired);
                    const retryConfig = {
                        ...error.config,
                        headers: {
                            ...error.config.headers,
                            'X-PAYMENT': signedPayload,
                        },
                    };

                    return await axiosInstance(retryConfig);
                } catch (signError) {
                    return Promise.reject(signError);
                }
            }
            return Promise.reject(error);
        },
    );

    return axiosInstance;
}