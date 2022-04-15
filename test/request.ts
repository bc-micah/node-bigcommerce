/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/ban-ts-comment */
import Request from '../src/request';
import nock from 'nock';
import { HttpsAgent } from 'agentkeepalive';
import zlib from 'zlib';

describe('Request', () => {
  const self: any = {};

  const request = new Request('api.bigcommerce.com', {
    headers: { 'Content-Type': 'application/json' }
  });

  afterEach(() => nock.cleanAll());

  describe('given a missing hostname', () => {
    it('should return an error if hostname is missing', () => {
      expect(() => {
        // @ts-ignore
        new Request();
      }).toThrowError(Error);
    });
  });

  describe('given a 429 status code', () => {
    beforeEach(() => {
      self.ordersCall = nock('https://api.bigcommerce.com')
        .post('/orders')
        .reply(429, {}, { 'X-Retry-After': '0.1' })
        .post('/orders')
        .reply(200, {});
    });

    it('should retry the request', async () => {
      await request.run('post', '/orders');
      expect(self.ordersCall.isDone()).toBe(true);
    });

    describe('given a failOnLimitReached option', () => {
      const failRequest = new Request('api.bigcommerce.com', {
        headers: { 'Content-Type': 'application/json' },
        failOnLimitReached: true
      });

      it('should return an error', async () => {
        let error: any;
        try {
          await failRequest.run('post', '/orders');
        } catch (err) {
          error = err;
        }
        expect(error.message).toMatch(/rate limit/);
        expect(error.retryAfter).toBe(0.1);
      });
    });
  });

  describe('given a bad request or internal error is returned', () => {
    beforeEach(() => {
      nock('https://api.bigcommerce.com').post('/orders').reply(400, {});
    });

    it('should return an error', async () => {
      await expect(() => request.run('post', '/orders', {})).rejects.toThrow(
        /Request returned error code/
      );
    });
  });

  describe('if "error" are found in the response JSON', () => {
    beforeEach(() => {
      nock('https://api.bigcommerce.com')
        .post('/orders')
        .reply(200, { error: 'An error has occurred.' });
    });

    it('should return an error', async () => {
      await expect(() => request.run('post', '/orders', {})).rejects.toThrow(
        /An error has occurred/
      );
    });
  });

  describe('if "errors" are found in the response JSON', () => {
    beforeEach(() => {
      nock('https://api.bigcommerce.com')
        .post('/orders')
        .reply(200, { errors: ['An error has occurred.'] });
    });

    it('should return an error', async () => {
      await expect(request.run('post', '/orders', {})).rejects.toThrow(
        /An error has occurred/
      );
    });
  });

  describe('given a malformed request JSON', () => {
    beforeEach(() => {
      nock('https://api.bigcommerce.com')
        .defaultReplyHeaders({ 'Content-Type': 'application/json' })
        .post('/orders')
        .reply(200, '<malformed>');
    });

    it('should return an error', async () => {
      await expect(request.run('post', '/orders', {})).rejects.toThrow(
        /Unexpected token/
      );
    });
  });

  describe('if json is not returned', () => {
    beforeEach(() => {
      nock('https://api.bigcommerce.com')
        .defaultReplyHeaders({ 'Content-Type': 'application/xml' })
        .post('/orders')
        .reply(200, '<xml></xml>');
      nock('https://api.bigcommerce.com')
        .defaultReplyHeaders({ 'Content-Type': 'application/json' })
        .post('/customers')
        .reply(200, '<html></html>');
    });

    it('should return the raw response', async () => {
      const res = await request.run('post', '/orders', {});
      expect(res).toBe('<xml></xml>');
    });

    it('should attach the response if the JSON cannot be parsed', async () => {
      await expect(() =>
        request.run('post', '/customers', {})
      ).rejects.toHaveProperty('responseBody');
    });
  });

  describe('timeout', () => {
    beforeEach(() => {
      nock('https://api.bigcommerce.com')
        .post('/orders')
        .replyWithError('ECONNRESET');
    });

    it('should return an error', async () => {
      await expect(() =>
        request.run('post', '/orders', {})
      ).rejects.toThrowError(/ECONNRESET/);
    });
  });

  it('should attach a keep-alive HTTPS agent', async () => {
    nock('https://api.bigcommerce.com')
      .post('/orders')
      .reply(200, { order: true });

    const request = new Request('api.bigcommerce.com', {
      headers: { 'Content-Type': 'application/json' },
      agent: new HttpsAgent({
        maxSockets: 30,
        maxFreeSockets: 30,
        timeout: 60000,
        keepAlive: true,
        keepAliveMsecs: 30000
      })
    });

    const res = await request.run('post', '/orders');
    expect(typeof res).toBe('object');
  });

  it('should return a JSON object on success', async () => {
    nock('https://api.bigcommerce.com')
      .post('/orders')
      .reply(200, { order: true });

    const res = await request.run('post', '/orders');
    expect(typeof res).toBe('object');
    expect(res.order).toBeTruthy();
  });

  it('should accept and parse a GZIP JSON response', async () => {
    const data = JSON.stringify({ order: true });
    const buffer = Buffer.from(data);
    const zipped = zlib.gzipSync(buffer);
    nock('https://api.bigcommerce.com')
      .post('/orders')
      .reply(200, zipped, {
        'X-Transfer-Length': String(zipped.length),
        'Content-Length': undefined,
        'Content-Encoding': 'gzip',
        'Content-Type': 'application/json'
      } as any);

    const request = new Request('api.bigcommerce.com', {
      headers: {
        'Content-Type': 'application/json',
        'Accept-Encoding': 'gzip, deflate'
      }
    });

    const res = await request.run('post', '/orders');
    expect(res).toBeDefined();
    expect(res).toHaveProperty('order', true);
  });

  it('should accept and parse a non-GZIP JSON response', async () => {
    const data = JSON.stringify({ order: true });
    const buffer = Buffer.from(data);

    nock('https://api.bigcommerce.com')
      .post('/orders')
      .reply(200, buffer, {
        'X-Transfer-Length': String(buffer.length),
        'Content-Length': undefined,
        'Content-Type': 'application/json'
      } as any);

    const request = new Request('api.bigcommerce.com', {
      headers: {
        'Content-Type': 'application/json',
        'Accept-Encoding': '*'
      }
    });

    const res = await request.run('post', '/orders');
    expect(res).toBeDefined();
    expect(res).toHaveProperty('order', true);
  });
});
