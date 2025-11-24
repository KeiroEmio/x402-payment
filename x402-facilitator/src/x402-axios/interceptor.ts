import type { AxiosInstance } from 'axios';
import type { ISigner } from './types';
import { PaymentRequirement } from '../types/PaymentRequired';

export function withPaymentInterceptor(
    axiosInstance: AxiosInstance,
    signer: ISigner,
): AxiosInstance {
    axiosInstance.interceptors.request.use(async (config) => {
        if (!config.headers['X-PAYMENT']) {
            // 这里可以直接返回 config，实际拦截逻辑放在 response 拦截器
            return config;
        }
        return config;
    });

    axiosInstance.interceptors.response.use(
        (response) => response,
        async (error) => {
            const { response } = error;
            if (response && response.status === 402 && response.data?.PaymentRequirement) {
                const PaymentRequirement = response.data.PaymentRequirement as PaymentRequirement;
                const signedPayment = await signer.offSignTransaction(PaymentRequirement);
                // 重新发起请求，带上 X-PAYMENT header
                const retryConfig = {
                    ...response.config,
                    headers: {
                        ...response.config.headers,
                        'X-PAYMENT': signedPayment,
                    },
                };
                return axiosInstance.request(retryConfig);
            }
            return Promise.reject(error);
        }
    );
    return axiosInstance;
}