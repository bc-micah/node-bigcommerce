import { verify, sign, JwtPayload } from 'jsonwebtoken';
import { isIP } from 'net';
import type { OutgoingHttpHeaders, Agent } from 'http';

import { debug } from 'debug';
import { timingSafeEqual, createHmac, randomBytes } from 'crypto';
import { Request } from './request';

const logger = debug('node-bigcommerce:bigcommerce');

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
  apiVersion: 'v2' | 'v3' = 'v2';
  constructor(config: Config) {
    if (!config) {
      throw new Error(
        'Config missing. The config object is required to make any call to the ' +
          'BigCommerce API'
      );
    }
    if (config.apiVersion) {
      this.apiVersion = config.apiVersion;
    }
    this.config = config;
  }

  /** Verify legacy signed_payload (can be ignored in favor of JWT) **/
  verify(signedRequest: string) {
    if (!signedRequest) {
      throw new Error('The signed request is required to verify the call.');
    }

    const splitRequest = signedRequest.split('.');
    if (splitRequest.length < 2) {
      throw new Error(
        'The signed request will come in two parts seperated by a .(full stop). ' +
          'this signed request contains less than 2 parts.'
      );
    }

    const signature = Buffer.from(splitRequest[1], 'base64').toString('utf8');
    const json = Buffer.from(splitRequest[0], 'base64').toString('utf8');
    const data = JSON.parse(json);

    logger('JSON: ' + json);
    logger('Signature: ' + signature);

    const expected = createHmac('sha256', this.config.secret)
      .update(json)
      .digest('hex');

    logger('Expected Signature: ' + expected);

    if (
      expected.length !== signature.length ||
      !timingSafeEqual(
        Buffer.from(expected, 'utf8'),
        Buffer.from(signature, 'utf8')
      )
    ) {
      throw new Error('Signature is invalid');
    }

    logger('Signature is valid');
    return data;
  }

  /** Verify signed_payload_jwt from load callback or constructed from constructJwtFromAuthData
   * @param signedRequestJwt
   * @returns object
   */
  verifyJWT(signedRequestJwt: string): string | JwtPayload {
    return verify(signedRequestJwt, this.config.secret, {
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
  constructJWTFromAuthData(
    user: { id: number; email: string },
    context: string,
    url: string
  ) {
    return sign(
      {
        aud: this.config.clientId,
        iss: this.config.clientId,
        sub: context,
        user,
        owner: user,
        url: url || '/'
      },
      this.config.secret,
      { expiresIn: '24h', algorithm: 'HS256' }
    );
  }

  /** Construct a JWT for customer login https://developer.bigcommerce.com/api-docs/storefront/customer-login-api
   * @param customerId
   * @param channelId
   * @param options
   * @returns string
   */
  async createCustomerLoginJWT(
    customerId: number,
    channelId = 1,
    options: SignJWTOptions = {}
  ): Promise<string> {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const payload: any = {
      iss: this.config.clientId,
      operation: 'customer_login',
      store_hash: this.config.storeHash,
      customer_id: customerId,
      channel_id: channelId,
      jti: randomBytes(32).toString('hex')
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
      if (isIP(options.requestIP) === 0) {
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
    } else {
      payload.iat = Math.floor(Date.now() / 1000);
    }

    return sign(payload, this.config.secret, {
      expiresIn: '24h',
      algorithm: 'HS256'
    });
  }

  authorize(query: { code: string; scope: string; context: string }) {
    if (!query) throw new Error('The URL query parameters are required.');

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

    const request = new Request(loginUrl, {
      failOnLimitReached: this.config.failOnLimitReached
    });

    return request.run('post', '/oauth2/token', payload);
  }

  createAPIRequest() {
    const accept =
      this.config.responseType === 'xml'
        ? 'application/xml'
        : 'application/json';

    const apiUrl = this.config.apiUrl || 'api.bigcommerce.com';

    return new Request(apiUrl, {
      headers: Object.assign(
        {
          Accept: accept,
          'X-Auth-Client': this.config.clientId,
          'X-Auth-Token': this.config.accessToken
        },
        this.config.headers || {}
      ),
      failOnLimitReached: this.config.failOnLimitReached,
      agent: this.config.agent
    });
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  request(method: string, path: string, data?: any): Promise<any> {
    if (!this.config.accessToken || !this.config.storeHash) {
      throw new Error(
        'Get request error: the access token and store hash are required to ' +
          'call the BigCommerce API'
      );
    }

    const extension = this.config.responseType === 'xml' ? '.xml' : '';
    const version = this.apiVersion;

    const request = this.createAPIRequest();

    let fullPath = `/stores/${this.config.storeHash}/${version}`;
    if (version !== 'v3') {
      fullPath += path.replace(/(\?|$)/, extension + '$1');
    } else {
      fullPath += path;
    }

    return request.run(method.toUpperCase(), fullPath, data);
  }

  getTime(): Promise<number> {
    const request = this.createAPIRequest();

    return request
      .run('GET', `/stores/${this.config.storeHash}/v2/time`)
      .then((resp: { time: number }) => resp.time);
  }

  get(path: string) {
    return this.request('GET', path);
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  post(path: string, data: any) {
    return this.request('POST', path, data);
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  put(path: string, data: any) {
    return this.request('PUT', path, data);
  }

  delete(path: string) {
    return this.request('DELETE', path);
  }
}
