'use strict';

let url = require('url');
let querystring = require('querystring');
let chai = require('chai');
let hmacValidator = require('../src/hmac-validator');

let expect = chai.expect;

describe('shopify signature', () => {
  const secret = 'hush';
  let hval;

  before(() => {
    hval = hmacValidator({
      replacements: {
        both: {
          '&': '%26',
          '%': '%25'
        },
        keys: {
          '=': '%3D'
        }
      },
      excludedKeys: ['signature', 'hmac'],
      algorithm: 'sha256',
      format: 'hex',
      digestKey: 'hmac'
    });
  });

  it('is correctly verified', () => {
    // Example got from: https://docs.shopify.com/api/guides/authentication/oauth
    // Request URL as a Node HTTP server get from an IncomingMessge
    // https://nodejs.org/api/http.html#http_class_http_incomingmessage
    const reqURL = '/?shop=some-shop.myshopify.com&timestamp=1337178173&signature=6e39a2ea9e497af6cb806720da1f1bf3&hmac=c2812f39f84c32c2edaded339a1388abc9829babf351b684ab797f04cd94d4c7';

    // 1. Parse the string URL to object
    const urlObj = url.parse(reqURL);
    // 2. Get the 'query string' portion
    const query = urlObj.search.slice(1);
    // 3. Verify signature
    const isValid = hval(secret, null, query);

    expect(isValid).to.be.true;
  });
});

describe('twilio signature', () => {
  const secret = '12345';
  let hval;

  before(() => {
    hval = hmacValidator({
      algorithm: 'sha1',
      format: 'base64',
      keyValueLink: '',
      pairsLink: ''
    });
  });

  it('is correctly verified', () => {
    // Example got from: https://www.twilio.com/docs/api/security
    // Request URL as a Node HTTP server get from an IncomingMessge
    // https://nodejs.org/api/http.html#http_class_http_incomingmessage
    const reqURL = '/myapp.php?foo=1&bar=2';
    // The body of the incoming message which is in JSON, but we avoid to do all those tasks,
    // they are out of the scope of example we set the object right away
    const body = {
      Digits: 1234,
      To: '+18005551212',
      From: '+14158675309',
      Caller: '+14158675309',
      CallSid: 'CA1234567890ABCDE'
    };

    // 1. Get the the whole URL, protocol, host, port, path & query
    const urlString = `https://mycompany.com${reqURL}`;
    // 2. From IncommingMessage objec we can get the X-Twilio-Signature in this example we set for simplicity
    const digest = 'RSOYDt4T1cUTdK1PDd93/VVr8B8=';
    // 3. Veryify signature
    // I'm not able to concatenate the URL
    const isValid = hval(secret, urlString, body, digest);

    expect(isValid).to.be.true;
  });
});

describe('pusher signature', () => {
  const secret = '7ad3773142a6692b25b8';
  let hval;

  before(() => {
    hval = hmacValidator({
      algorithm: 'sha256',
      format: 'hex'
    });
  });

  it('is correctly verified', () => {
    // Example got from: https://pusher.com/docs/auth_signatures
    // Request URL as a Node HTTP server get from an IncomingMessge
    // https://nodejs.org/api/http.html#http_class_http_incomingmessage
    const reqURL = '/pusher/auth?channel_name=presence-foobar&socket_id=1234.1234';

    // 1. From IncommingMessage objec we can get the X-Pusher-Signature in this example we set for simplicity
    const digest = 'afaed3695da2ffd16931f457e338e6c9f2921fa133ce7dac49f529792be6304c';
    // 2. The body of the incoming message which is in JSON; the value must be used without parsing
    const body = '{"user_id":10,"user_info":{"name":"Mr. Pusher"}}';
    // 3. Compose the payload which has been used, by Pusher, to create the signature
    // 3.1. Parse the string URL to object
    const urlObj = url.parse(reqURL);
    // 3.2 Extract values and concatenate with raw JSON body
    const queryMap = querystring.parse(urlObj.query);
    const payload = `${queryMap.socket_id}:${queryMap.channel_name}:${body}`;
    // 4. Verify signature, payload is provided as prefix because it's a string wich doen't require any tranformation
    // moreover providing it as `payload` (3rd parameter) would be parsed as a query string, so it isn' the case
    // tha we want
    const isValid = hval(secret, payload, null, digest);

    expect(isValid).to.be.true;
  });
});
