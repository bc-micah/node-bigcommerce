/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/ban-ts-comment */
import jwt, { JwtPayload } from 'jsonwebtoken';

import BigCommerce from '../src/bigcommerce';
import Request from '../src/request';
import * as sinon from 'sinon';

const DEFAULT_CONFIG = {
  secret: '123456abcdef',
  clientId: '123456abcdef',
  callback: 'http://foo.com',
  accessToken: '123456',
  storeHash: '12abc'
};

describe('BigCommerce', () => {
  const self: any = {};

  const bc = new BigCommerce(DEFAULT_CONFIG);

  beforeEach(() => (self.sandbox = sinon.createSandbox()));
  afterEach(() => self.sandbox.restore());

  describe('#constructor', () => {
    it('should return an error if config is missing', () => {
      expect(() => {
        // @ts-ignore
        new BigCommerce();
      }).toThrow();
    });

    it('should save config to the object', () => {
      const newBc = new BigCommerce(DEFAULT_CONFIG);
      expect(newBc.config).toBeInstanceOf(Object);
      expect(newBc.apiVersion).toBe('v2');
    });

    it('should set api version to a default', () => {
      expect(
        new BigCommerce({
          ...DEFAULT_CONFIG,
          apiVersion: 'v3'
        }).apiVersion
      ).toBe('v3');
    });
  });

  describe('#verify', () => {
    describe('given a null signed request', () => {
      it('should return null', () => {
        expect(() => {
          // @ts-ignore
          bc.verify();
        }).toThrowError(/signed request is required/);
      });
    });

    describe('given a signed request without a full stop', () => {
      it('should return null', () => {
        expect(() => bc.verify('12345')).toThrowError(/full stop/);
      });
    });

    describe('given an invalid signature', () => {
      it('should return null', () => {
        expect(() => {
          bc.verify(
            'eyJmb28iOiJmb28ifQ==.YjMzMTQ2ZGU4ZTUzNWJiOTI3NTI1ODJmNzhiZGM5NzBjNGQ3MjZkZDdkMDY1MjdkZGYxZDA0NGZjNDVjYmNkMQ=='
          );
        }).toThrowError(/invalid/);
      });
    });

    describe('given an invalid signature (different length)', () => {
      it('should return null', () => {
        expect(() => {
          bc.verify('eyJmb28iOiJmb28ifQ==.Zm9v');
        }).toThrowError(/invalid/);
      });
    });

    it('should return the JSON data', () => {
      const verify = bc.verify(
        'eyJmb28iOiJmb28ifQ==.YjMzMTQ2ZGU4ZTUzNWJiOTI3NTI1ODJmNzhiZGM' +
          '5NzBjNGQ3MjZkZDdkMDY1MjdkZGYxZDA0NGZjNDVjYmNkMA=='
      );
      expect(verify.foo).toBe('foo');
    });
  });

  describe('#verifyJWT', () => {
    describe('given a null JWT', () => {
      it('should return error', () => {
        expect(() => {
          // @ts-ignore
          bc.verifyJWT();
        }).toThrowError(/jwt must be provided/);
      });
    });

    describe('given an invalid signature', () => {
      it('should return an error', () => {
        expect(() =>
          bc.verifyJWT(
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiIxMjM0NTZhYmNkZWYiLCJpc3MiOiJiYyIsImlhdCI6MTYyMjc0MjcyNywibmJmIjoxNjIyNzQyNzIyLCJleHAiOjMxMjI4MjkxMjcsImp0aSI6ImY0NGI1NmU5LTI1ZTUtNDQ3OC05ODUyLTQwMjdlNzMyYmY0OSIsInN1YiI6InN0b3Jlcy8xMmFiYyIsInVzZXIiOnsiaWQiOjIzNjksImVtYWlsIjoidGVzdEB0ZXN0LnRlc3QifSwib3duZXIiOnsiaWQiOjIzNjksImVtYWlsIjoidGVzdEB0ZXN0LnRlc3QifSwidXJsIjoiLyJ9.61QXFp-vG9yN7KK9M56PMOdv5lWAFt4u4jv8C8slSqA'
          )
        ).toThrowError(/invalid/);
      });
    });

    it('should return the JSON data', () => {
      const verify = bc.verifyJWT(
        'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiIxMjM0NTZhYmNkZWYiLCJpc3MiOiJiYyIsImlhdCI6MTYyMjc0MjcyNywibmJmIjoxNjIyNzQyNzIyLCJleHAiOjM2MjI4MjkxMjcsImp0aSI6ImY0NGI1NmU5LTI1ZTUtNDQ3OC05ODUyLTQwMjdlNzMyYmY0OSIsInN1YiI6InN0b3Jlcy8xMmFiYyIsInVzZXIiOnsiaWQiOjIzNjksImVtYWlsIjoidGVzdEB0ZXN0LnRlc3QifSwib3duZXIiOnsiaWQiOjIzNjksImVtYWlsIjoidGVzdEB0ZXN0LnRlc3QifSwidXJsIjoiLyJ9.QRTvS1SVBEPrnBb2woA16sbFvNjb8b0vzwF17sVNYV4'
      );
      expect(verify.sub).toBe('stores/12abc');
    });
  });

  describe('#constructJWTFromAuthData', () => {
    describe('given auth callback data', () => {
      it('should return a valid jwt', () => {
        const authServiceResponse = {
          access_token: 'ACCESS_TOKEN',
          scope: 'store_v2_orders',
          user: {
            id: 24654,
            email: 'merchant@mybigcommerce.com'
          },
          context: 'stores/12abc'
        };
        const verify = bc.verifyJWT(
          bc.constructJWTFromAuthData(
            authServiceResponse.user,
            authServiceResponse.context,
            '/'
          )
        );
        expect(verify.sub).toBe('stores/12abc');
      });
    });
  });

  describe('#createCustomerLoginJWT', () => {
    describe('given a customer ID and channel ID', () => {
      it('should return a valid jwt', async () => {
        const loginJWT = await bc.createCustomerLoginJWT(1);
        const iat = (jwt.verify(loginJWT, bc.config.secret) as JwtPayload)
          .iat as number;
        expect(iat).toBeDefined();
        expect(Math.floor(iat - Math.floor(Date.now() / 1000))).toBe(0);
        expect(
          (jwt.verify(loginJWT, bc.config.secret) as JwtPayload).store_hash
        ).toBe('12abc');
        // We've already verified, so now just decode
        expect((jwt.decode(loginJWT) as JwtPayload).customer_id).toBe(1);
        expect((jwt.decode(loginJWT) as JwtPayload).channel_id).toBe(1);
        expect((jwt.decode(loginJWT) as JwtPayload).operation).toBe(
          'customer_login'
        );
        expect((jwt.decode(loginJWT) as JwtPayload).iss).toBe(
          bc.config.clientId
        );

        expect(
          (jwt.decode(loginJWT) as JwtPayload).jti?.length
        ).toBeGreaterThan(20);
      });
    });
  });

  describe('#authorize', () => {
    beforeEach(() => {
      self.runStub = self.sandbox
        .stub(Request.prototype, 'run')
        .returns(Promise.resolve({ test: true }));
    });

    const query = { code: '', scope: '', context: '' };

    it('should return an object', async () => {
      const data = bc.authorize(query);
      expect(data).toBeDefined();
    });

    describe('when the query params are missing', () => {
      it('should return an error', async () => {
        await expect(async () => {
          // @ts-ignore
          return bc.authorize(null);
        }).rejects.toThrow(/are required/);
      });
    });

    describe('when the authorization fails', () => {
      beforeEach(() => {
        self.runStub.returns(Promise.reject(new Error('foo')));
      });

      it('should return and error', async () => {
        await expect(async () => {
          return bc.authorize(query);
        }).rejects.toThrow(/foo/);
      });
    });
  });

  describe('#createAPIRequest', () => {
    it('should create a request object with the correct headers', () => {
      const request = bc.createAPIRequest();
      expect(request.headers['X-Auth-Client']).toBe('123456abcdef');
      expect(request.headers['X-Auth-Token']).toBe('123456');
    });

    it('should have the correct API hostname', () => {
      const request = bc.createAPIRequest();
      expect(request.hostname).toBe('api.bigcommerce.com');
    });
  });

  describe('#request', () => {
    beforeEach(() => {
      self.requestStub = self.sandbox
        .stub(Request.prototype, 'run')
        .returns(Promise.resolve({ text: '' }));
    });

    it('should make a call to the request object', () => {
      return bc
        .request('get', '/foo')
        .then(() => sinon.assert.calledOnce(self.requestStub));
    });

    it('should use v3 if specified in config', () => {
      const bcV3 = new BigCommerce({
        secret: '123456abcdef',
        clientId: '123456abcdef',
        callback: 'http://foo.com',
        accessToken: '123456',
        storeHash: '12abc',
        apiVersion: 'v3'
      });

      return bcV3
        .request('GET', '/themes')
        .then(() =>
          sinon.assert.calledWith(
            self.requestStub,
            'GET',
            '/stores/12abc/v3/themes'
          )
        );
    });

    describe('when the header requirements are not met', () => {
      it('should return an error', async () => {
        const bc = new BigCommerce({} as any);
        await expect(async () => {
          await bc.request('GET', '/foo');
        }).rejects.toThrowError(/access token/);
      });
    });

    describe('when the response type is xml', () => {
      const xmlBc = new BigCommerce({
        ...DEFAULT_CONFIG,
        responseType: 'xml'
      });

      it('should call the request object with extension .xml', () => {
        return xmlBc
          .request('GET', '/foo')
          .then(() =>
            sinon.assert.calledWith(
              self.requestStub,
              'GET',
              '/stores/12abc/v2/foo.xml',
              undefined
            )
          );
      });
    });

    describe('when the response type is json', () => {
      it('should make a call to the request object with an empty extension', () => {
        const jsonBc = new BigCommerce({
          accessToken: '123456',
          clientId: 'abcdef',
          secret: 'abcd',
          storeHash: 'abcd/1',
          responseType: 'json'
        });

        return jsonBc
          .request('GET', '/foo')
          .then(() =>
            sinon.assert.calledWith(
              self.requestStub,
              'GET',
              '/stores/abcd/1/v2/foo',
              undefined
            )
          );
      });
    });
  });

  describe('#get', () => {
    beforeEach(() => {
      self.requestStub = self.sandbox
        .stub(Request.prototype, 'run')
        .returns(Promise.resolve({ text: '' }));
    });

    it('should make a request with the correct arguments', () => {
      return bc.get('/foo').then((res) => {
        expect(res).toEqual({ text: '' });
        sinon.assert.calledWith(
          self.requestStub,
          'GET',
          '/stores/12abc/v2/foo',
          undefined
        );
      });
    });
  });

  describe('#post', () => {
    beforeEach(() => {
      self.requestStub = self.sandbox
        .stub(Request.prototype, 'run')
        .returns(Promise.resolve({ text: '' }));
    });

    it('should make a request with the correct arguments', () => {
      return bc.post('/foo', { foo: 'bar' }).then((res) => {
        expect(res).toEqual({ text: '' });
        sinon.assert.calledWith(
          self.requestStub,
          'POST',
          '/stores/12abc/v2/foo',
          { foo: 'bar' }
        );
      });
    });
  });

  describe('#put', () => {
    beforeEach(() => {
      self.requestStub = self.sandbox
        .stub(Request.prototype, 'run')
        .returns(Promise.resolve({ text: '' }));
    });

    it('should make a request with the correct arguments', () => {
      return bc.put('/foo', { foo: 'bar' }).then((res) => {
        expect(res).toEqual({ text: '' });
        sinon.assert.calledWith(
          self.requestStub,
          'PUT',
          '/stores/12abc/v2/foo',
          { foo: 'bar' }
        );
      });
    });
  });

  describe('#delete', () => {
    beforeEach(() => {
      self.requestStub = self.sandbox
        .stub(Request.prototype, 'run')
        .returns(Promise.resolve({ text: '' }));
    });

    it('should make a request with the correct arguments', () => {
      return bc.delete('/foo').then((res) => {
        expect(res).toEqual({ text: '' });
        sinon.assert.calledWith(
          self.requestStub,
          'DELETE',
          '/stores/12abc/v2/foo',
          undefined
        );
      });
    });
  });
});
