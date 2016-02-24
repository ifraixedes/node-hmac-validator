'use strict';

let chai = require('chai');
let hmacValidator = require('../src/hmac-validator');

let expect = chai.expect;

describe('hmac validator', () => {
  const secret = 'hush';
  let commonConfig = {
    replacements: {
      both: {
        '&': '%26',
        '%': '%25'
      },
      keys: {
        '=': '%3D',
        '^': '5E'
      },
      values: {
        '<': '#60',
        '>': '#62'
      }
    },
    excludedKeys: ['signature', 'hmac'],
    algorithm: 'sha256',
    format: 'hex'
  };

  it('throws an error when missing a required configuration parameters', () => {
    expect(hmacValidator.bind(null, { format: 'hex' })).to.throw(/configuration isn't an object with the required properties:/i);
    expect(hmacValidator.bind(null, { altorithm: 'sha256' })).to.throw(/configuration isn't an object with the required properties:/i);

    expect(hmacValidator.bind(null, { algorithm: 'sha256', format: 'hex', replacements: { both: { too: 'large' } } }))
    .to.throw(/invalid replacement: object properties for keys, values & both must be exactly 1 character/i);
  });

  it('allows to check query strings providing digest to compare', () => {
    let validate = hmacValidator(commonConfig);
    let digest = 'c2812f39f84c32c2edaded339a1388abc9829babf351b684ab797f04cd94d4c7';

    let c = validate(
      secret,
      null,
      'shop=some-shop.myshopify.com&timestamp=1337178173&signature=6e39a2ea9e497af6cb806720da1f1bf3&hmac=c2812f39f84c32c2edaded339a1388abc9829babf351b684ab797f04cd94d4c7',
      digest);

    expect(c).to.be.true;
  });

  it('throws an error to check when digest is not inside of the payload and it is not provided', () => {
    let validate = hmacValidator(commonConfig);

    expect(
      validate.bind(null, secret, null, 'shop=some-shop.myshopify.com&timestamp=1337178173&signature=6e39a2ea9e497af6cb806720da1f1bf3&hmac=c2812f39f84c32c2edaded339a1388abc9829babf351b684ab797f04cd94d4c7')
    ).to.throw(/Digest should be provided because not digest key was set/);
  });

  it('allows to check query strings provding digest as a key inside of the query string', () => {
    let validate = hmacValidator(Object.assign({},
      commonConfig, {
        digestKey: 'hmac'
      }));

    let c = validate(secret, null, 'shop=some-shop.myshopify.com&timestamp=1337178173&signature=6e39a2ea9e497af6cb806720da1f1bf3&hmac=c2812f39f84c32c2edaded339a1388abc9829babf351b684ab797f04cd94d4c7');
    expect(c).to.be.true;
  });

  it('allows to check objects (key/value) providing a digest to compare', () => {
    let validate = hmacValidator(commonConfig);
    let digest = 'c2812f39f84c32c2edaded339a1388abc9829babf351b684ab797f04cd94d4c7';

    let c = validate(secret, null, {
      shop: 'some-shop.myshopify.com',
      timestamp: '1337178173',
      signature: '6e39a2ea9e497af6cb806720da1f1bf3'
    }, digest);

    expect(c).to.be.true;
  });

  it('allows to check objects (key/value) providing an INVALID digest to compare', () => {
    let validate = hmacValidator(commonConfig);
    let digest = 'a2812f39f84c32c2edaded339a1388abc9829babf351b684ab797f04cd94d4c8';

    let c = validate(secret, null, {
      shop: 'some-shop.myshopify.com',
      timestamp: '1337178173',
      signature: '6e39a2ea9e497af6cb806720da1f1bf3'
    }, digest);

    expect(c).to.be.false;
  });

  it('allows to check objects (key/value) providing a digest as key', () => {
    let validate = hmacValidator(
      Object.assign({}, commonConfig, { digestKey: 'hmac' }));

    let c = validate(secret, null, {
      shop: 'some-shop.myshopify.com',
      timestamp: '1337178173',
      signature: '6e39a2ea9e497af6cb806720da1f1bf3',
      hmac: 'c2812f39f84c32c2edaded339a1388abc9829babf351b684ab797f04cd94d4c7'
    });

    expect(c).to.be.true;
  });

  it('allows to check objects (key/value) providing a digest as key which is not included as excluded key', () => {
    let validate = hmacValidator(
      Object.assign({}, commonConfig, { digestKey: 'hmac', excludedKeys: ['signature'] }));

    let c = validate(secret, null, {
      shop: 'some-shop.myshopify.com',
      timestamp: '1337178173',
      signature: '6e39a2ea9e497af6cb806720da1f1bf3',
      hmac: 'c2812f39f84c32c2edaded339a1388abc9829babf351b684ab797f04cd94d4c7'
    });

    expect(c).to.be.true;
  });

  it('allows to check objects (key/value) providing an INVALID digest as key', () => {
    let validate = hmacValidator(
      Object.assign({}, commonConfig, { digestKey: 'hmac' }));

    let c = validate(secret, null, {
      shop: 'some-shop.myshopify.com',
      timestamp: '1337178173',
      signature: '6e39a2ea9e497af6cb806720da1f1bf3',
      hmac: 'a2812f39f84c32c2edaded339a1388abc9829babf351b684ab797f04cd94d4c8'
    });

    expect(c).to.be.false;
  });

  it('allows to replace certain characters from keys', () => {
    let validate = hmacValidator(commonConfig);
    let digest = '3328f4347728f5c0ed778c3557ac68e9b1b7d88d0154fc1a3cdf3cb3ee52c309';

    let c = validate(
      secret,
      null,
      'shop=some-shop.myshopify.com&time%stamp=1337178173&sign^ature=6e39a2ea9e497af6cb806720da1f1bf3',
      digest);

    expect(c).to.be.true;
  });

  it('allows to replace certain characters from values', () => {
    let validate = hmacValidator(commonConfig);
    let digest = '262d203d7dbf52b26d079691e286318f6b9c53fb41994f396ce84ff4cbb43b34';

    let c = validate(
      secret,
      null,
      'shop=some-shop.myshopify.com&timestamp=1337<17>8173&signature=6e39a2ea9e497af6cb806720da1f1bf3',
      digest);

    expect(c).to.be.true;
  });

  it('allows to replace certain characters from keys & values', () => {
    let validate = hmacValidator(commonConfig);
    let digest = 'b915e8f59ddd5a64fb03619796fde51f3b049de6e68e2b334d3fe386e64b9969';

    let c = validate(
      secret,
      null,
      'shop=some-shop.myshopify.com&time%stamp=1337<17>8173&signature=6e39a2ea9e497af6cb806720da1f1bf3',
      digest);

    expect(c).to.be.true;
  });

  it('makes replacements without replacing previous replacements', () => {
    let validate = hmacValidator(
      Object.assign({}, commonConfig, { digestKey: 'hmac' }));

    let c = validate(secret, null, {
      'sh=op': 'some-shop.myshopify.com',
      timestamp: '&1337178173',
      hmac: '81d1af737a90ad690042ffa0ad92cbebb98ae38ba2892fcb7a87fe61faf11947'
    });

    // Expected to generate this payload to after calculate the HMAC: sh%3Dop=some-shop.myshopify.com&timestamp=%261337178173
    expect(c).to.be.true;
  });

  it('throws an error if secret is not provided', () => {
    let validate = hmacValidator(commonConfig);
    let digest = '262d203d7dbf52b26d079691e286318f6b9c53fb41994f396ce84ff4cbb43b34';

    let c = validate.bind(null,
      undefined,
      null,
      'shop=some-shop.myshopify.com&timestamp=1337<17>8173&signature=6e39a2ea9e497af6cb806720da1f1bf3',
      digest);

    expect(c).to.throw(Error);
  });
});
