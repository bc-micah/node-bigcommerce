/// <reference types="node" />
import { JwtPayload } from 'jsonwebtoken';
import type { OutgoingHttpHeaders, Agent } from 'http';
import { Request } from './request';
/**
 * BigCommerce OAuth2 Authentication and API access
 *
 * @param {Object} config
 * @return null
 *
 * Example Config
 * {
 *   logLevel: 'info',
 *   clientId: 'hjasdfhj09sasd80dsf04dfhg90rsds',
 *   secret: 'odpdf83m40fmxcv0345cvfgh73bdwjc',
 *   callback: 'https://mysite.com/bigcommerce'
 *   accessToken: 'ly8cl3wwcyj12vpechm34fd20oqpnl',
 *   storeHash: 'x62tqn',
 *   responseType: 'json',
 *   headers: { 'Accept-Encoding': '*' }
 * }
 */
export interface Config {
    agent?: boolean | Agent;
    apiUrl?: string;
    logLevel?: 'info' | 'debug';
    clientId: string;
    secret: string;
    callback?: string;
    accessToken: string;
    storeHash: string;
    responseType?: 'json' | 'xml';
    headers?: OutgoingHttpHeaders;
    apiVersion?: 'v2' | 'v3';
    loginUrl?: string;
    failOnLimitReached?: boolean;
}
export interface SignJWTOptions {
    redirectUrl?: string;
    requestIP?: string;
    useBCTime?: boolean;
}
export default class BigCommerce {
    config: Config;
    apiVersion: 'v2' | 'v3';
    constructor(config: Config);
    /** Verify legacy signed_payload (can be ignored in favor of JWT) **/
    verify(signedRequest: string): any;
    /** Verify signed_payload_jwt from load callback or constructed from constructJwtFromAuthData
     * @param signedRequestJwt
     * @returns object
     */
    verifyJWT(signedRequestJwt: string): string | JwtPayload;
    /** Construct a JWT mimicking the format of the load callback from the auth callback data
     * to use in an app
     * (to minimize duplication of code related to handling callbacks)
     * callbacks
     * @param user
     * @param context
     * @param url
     * @returns string
     */
    constructJWTFromAuthData(user: {
        id: number;
        email: string;
    }, context: string, url: string): string;
    /** Construct a JWT for customer login https://developer.bigcommerce.com/api-docs/storefront/customer-login-api
     * @param customerId
     * @param channelId
     * @param options
     * @returns string
     */
    createCustomerLoginJWT(customerId: number, channelId?: number, options?: SignJWTOptions): Promise<string>;
    authorize(query: {
        code: string;
        scope: string;
        context: string;
    }): Promise<any>;
    createAPIRequest(): Request;
    request(method: string, path: string, data?: any): Promise<any>;
    getTime(): Promise<number>;
    get(path: string): Promise<any>;
    post(path: string, data: any): Promise<any>;
    put(path: string, data: any): Promise<any>;
    delete(path: string): Promise<any>;
}
