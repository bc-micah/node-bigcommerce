import { debug } from 'debug';
import { request, RequestOptions } from 'https';
import { createUnzip, Unzip } from 'zlib';

import type { OutgoingHttpHeaders, IncomingMessage, Agent } from 'http';

// used just for version
// using import bundles package.json twice
// eslint-disable-next-line @typescript-eslint/no-var-requires
const { version } = require('../package.json');
const logger = debug('node-bigcommerce:request');

/**
 * Parse response
 */
function parseResponse(
  res: IncomingMessage,
  body: string,
  resolve: (value: string | unknown) => void,
  reject: (err: Error) => void
) {
  const contentType = res.headers['content-type'];
  const isJSON =
    contentType !== undefined && contentType.indexOf('application/json') !== -1;
  if (!isJSON) {
    resolve(body);
  }

  try {
    const json = JSON.parse(body);
    const errors = json.error ? [json.error] : json.errors || [];
    if (errors.length > 0) {
      return reject(
        new APIError(`An error has occurred`, errors, body, res.statusCode)
      );
    } else {
      resolve(json);
    }
  } catch (err) {
    (err as ResponseError).responseBody = body;
    reject(err as Error);
  }
}

class LimitReachedError extends Error {
  public retryAfter: number;
  constructor(message: string, retryAfter: number) {
    super(message);

    this.retryAfter = retryAfter;
  }
}

class ResponseError extends Error {
  public code?: number;
  public responseBody: string;
  constructor(message: string, responseBody: string, code?: number) {
    super(message);

    this.responseBody = responseBody;
    this.code = code;
  }
}

class APIError extends ResponseError {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  public errors: any[];
  constructor(
    message: string,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    errors: any[],
    responseBody: string,
    code?: number
  ) {
    super(message, responseBody, code);

    this.errors = errors;
    this.responseBody = responseBody;
    this.code = code;
  }
}

export class Request {
  hostname: string;
  headers: OutgoingHttpHeaders = {};
  failOnLimitReached = false;
  agent: Agent | boolean | undefined = undefined;

  constructor(
    hostname: string,
    {
      headers,
      failOnLimitReached,
      agent
    }: {
      headers?: OutgoingHttpHeaders;
      failOnLimitReached?: boolean;
      agent?: Agent | boolean;
    } = {}
  ) {
    if (!hostname) {
      throw new Error(
        'The hostname is required to make the call to the server.'
      );
    }

    this.hostname = hostname;

    if (headers) {
      this.headers = headers;
    }

    if (failOnLimitReached) {
      this.failOnLimitReached = failOnLimitReached;
    }

    if (agent) {
      this.agent = agent;
    }
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  run(method: string, path: string, data: any = ''): Promise<any> {
    logger(
      `Requesting Data from: https://${this.hostname}${path} Using the ${method} method`
    );

    const dataString: string =
      typeof data == 'string' ? data : JSON.stringify(data);
    const dataBuffer = Buffer.from(dataString, 'utf-8');

    const options: RequestOptions = {
      path,
      hostname: this.hostname,
      method: method,
      port: 443,
      headers: Object.assign(
        {
          'User-Agent': 'node-bigcommerce/' + version,
          'Content-Type': 'application/json',
          'Accept-Encoding': 'gzip, deflate',
          'Content-Length': dataBuffer.length
        },
        this.headers
      ),
      agent: this.agent
    };

    logger('Starting Request, with options.', options);

    return new Promise((resolve, reject) => {
      const req = request(options, (res) => {
        logger('Status Returned: ' + res.statusCode);
        logger('Headers Returned: ' + JSON.stringify(res.headers));

        let stream: IncomingMessage | Unzip = res;

        // use stream unzip - like axios
        if (res.statusCode !== 204 && req.method !== 'HEAD') {
          switch (res.headers['content-encoding']) {
            /*eslint default-case:0*/
            case 'gzip':
            case 'compress':
            case 'deflate':
              stream = stream.pipe(createUnzip());
              break;
          }
        }

        const responseBuffer: Uint8Array[] = [];

        // If the API limit has been reached
        if (res.statusCode === 429) {
          const timeToWait = Number(res.headers['x-retry-after']);

          if (this.failOnLimitReached) {
            return reject(
              new LimitReachedError(
                `You have reached the rate limit for the BigCommerce API. Please retry in ${timeToWait} seconds.`,
                timeToWait
              )
            );
          }

          logger(
            `You have reached the rate limit for the BigCommerce API, we will retry again in ${timeToWait} seconds.`
          );

          return setTimeout(() => {
            logger('Restarting request call after suggested time');

            this.run(method, path, data).then(resolve).catch(reject);
          }, timeToWait * 1000);
        }

        stream.on('data', function handleStreamData(chunk) {
          responseBuffer.push(chunk);
        });

        stream.on('end', () => {
          logger('Request complete');
          const responseData = (
            responseBuffer.length === 1
              ? responseBuffer[0]
              : Buffer.concat(responseBuffer)
          ).toString('utf-8');

          if (
            res.statusCode != undefined &&
            res.statusCode >= 400 &&
            res.statusCode <= 600
          ) {
            return reject(
              new ResponseError(
                `Request returned error code: ${res.statusCode} and body: ${responseData}`,
                responseData,
                res.statusCode
              )
            );
          }

          return parseResponse(res, responseData, resolve, reject);
        });

        stream.on('error', (e) => reject(e));
      });

      req.on('error', (e) => reject(e));

      if (data) {
        logger('Sending Data: ' + dataString);
        req.end(dataBuffer);
      } else {
        req.end();
      }
    });
  }
}
export default Request;
