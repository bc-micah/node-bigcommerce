"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const jsonwebtoken_1 = require("jsonwebtoken");
const net_1 = require("net");
const debug_1 = require("debug");
const crypto_1 = require("crypto");
const request_1 = require("./request");
const logger = (0, debug_1.debug)('node-bigcommerce:bigcommerce');
class BigCommerce {
    constructor(config) {
        this.apiVersion = 'v2';
        if (!config) {
            throw new Error('Config missing. The config object is required to make any call to the ' +
                'BigCommerce API');
        }
        if (config.apiVersion) {
            this.apiVersion = config.apiVersion;
        }
        this.config = config;
    }
    /** Verify legacy signed_payload (can be ignored in favor of JWT) **/
    verify(signedRequest) {
        if (!signedRequest) {
            throw new Error('The signed request is required to verify the call.');
        }
        const splitRequest = signedRequest.split('.');
        if (splitRequest.length < 2) {
            throw new Error('The signed request will come in two parts seperated by a .(full stop). ' +
                'this signed request contains less than 2 parts.');
        }
        const signature = Buffer.from(splitRequest[1], 'base64').toString('utf8');
        const json = Buffer.from(splitRequest[0], 'base64').toString('utf8');
        const data = JSON.parse(json);
        logger('JSON: ' + json);
        logger('Signature: ' + signature);
        const expected = (0, crypto_1.createHmac)('sha256', this.config.secret)
            .update(json)
            .digest('hex');
        logger('Expected Signature: ' + expected);
        if (expected.length !== signature.length ||
            !(0, crypto_1.timingSafeEqual)(Buffer.from(expected, 'utf8'), Buffer.from(signature, 'utf8'))) {
            throw new Error('Signature is invalid');
        }
        logger('Signature is valid');
        return data;
    }
    /** Verify signed_payload_jwt from load callback or constructed from constructJwtFromAuthData
     * @param signedRequestJwt
     * @returns object
     */
    verifyJWT(signedRequestJwt) {
        return (0, jsonwebtoken_1.verify)(signedRequestJwt, this.config.secret, {
            algorithms: ['HS256'],
            audience: this.config.clientId
        });
    }
    /** Construct a JWT mimicking the format of the load callback from the auth callback data
     * to use in an app
     * (to minimize duplication of code related to handling callbacks)
     * callbacks
     * @param user
     * @param context
     * @param url
     * @returns string
     */
    constructJWTFromAuthData(user, context, url) {
        return (0, jsonwebtoken_1.sign)({
            aud: this.config.clientId,
            iss: this.config.clientId,
            sub: context,
            user,
            owner: user,
            url: url || '/'
        }, this.config.secret, { expiresIn: '24h', algorithm: 'HS256' });
    }
    /** Construct a JWT for customer login https://developer.bigcommerce.com/api-docs/storefront/customer-login-api
     * @param customerId
     * @param channelId
     * @param options
     * @returns string
     */
    async createCustomerLoginJWT(customerId, channelId = 1, options = {}) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const payload = {
            iss: this.config.clientId,
            operation: 'customer_login',
            store_hash: this.config.storeHash,
            customer_id: customerId,
            channel_id: channelId,
            jti: (0, crypto_1.randomBytes)(32).toString('hex')
        };
        /* Optional redirect URL (relative path on the storefront), e.g. '/shop-all/' */
        if (options.redirectUrl) {
            payload.redirect_url = options.redirectUrl;
        }
        /*
         * Optional end-user IP for extra security
         * The login will be rejected if it does not come from this IP
         */
        if (options.requestIP) {
            if ((0, net_1.isIP)(options.requestIP) === 0) {
                throw new Error('Invalid IP address');
            }
            payload.request_ip = options.requestIP;
        }
        /*
         * Run an API request to get the current server time from BC to use for the JWT generation
         * This is useful to prevent clock skew resulting in invalid JWTs
         */
        if (options.useBCTime) {
            payload.iat = await this.getTime();
        }
        else {
            payload.iat = Math.floor(Date.now() / 1000);
        }
        return (0, jsonwebtoken_1.sign)(payload, this.config.secret, {
            expiresIn: '24h',
            algorithm: 'HS256'
        });
    }
    authorize(query) {
        if (!query)
            throw new Error('The URL query parameters are required.');
        const payload = {
            client_id: this.config.clientId,
            client_secret: this.config.secret,
            redirect_uri: this.config.callback,
            grant_type: 'authorization_code',
            code: query.code,
            scope: query.scope,
            context: query.context
        };
        const loginUrl = this.config.loginUrl || 'login.bigcommerce.com';
        const request = new request_1.Request(loginUrl, {
            failOnLimitReached: this.config.failOnLimitReached
        });
        return request.run('post', '/oauth2/token', payload);
    }
    createAPIRequest() {
        const accept = this.config.responseType === 'xml'
            ? 'application/xml'
            : 'application/json';
        const apiUrl = this.config.apiUrl || 'api.bigcommerce.com';
        return new request_1.Request(apiUrl, {
            headers: Object.assign({
                Accept: accept,
                'X-Auth-Client': this.config.clientId,
                'X-Auth-Token': this.config.accessToken
            }, this.config.headers || {}),
            failOnLimitReached: this.config.failOnLimitReached,
            agent: this.config.agent
        });
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    request(method, path, data) {
        if (!this.config.accessToken || !this.config.storeHash) {
            throw new Error('Get request error: the access token and store hash are required to ' +
                'call the BigCommerce API');
        }
        const extension = this.config.responseType === 'xml' ? '.xml' : '';
        const version = this.apiVersion;
        const request = this.createAPIRequest();
        let fullPath = `/stores/${this.config.storeHash}/${version}`;
        if (version !== 'v3') {
            fullPath += path.replace(/(\?|$)/, extension + '$1');
        }
        else {
            fullPath += path;
        }
        return request.run(method.toUpperCase(), fullPath, data);
    }
    getTime() {
        const request = this.createAPIRequest();
        return request
            .run('GET', `/stores/${this.config.storeHash}/v2/time`)
            .then((resp) => resp.time);
    }
    get(path) {
        return this.request('GET', path);
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    post(path, data) {
        return this.request('POST', path, data);
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    put(path, data) {
        return this.request('PUT', path, data);
    }
    delete(path) {
        return this.request('DELETE', path);
    }
}
exports.default = BigCommerce;
