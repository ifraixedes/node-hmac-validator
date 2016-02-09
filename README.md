Node HMAC Validator
===================

A generic HMAC signature validator for NodeJS.

## Usage

The module exports just a function, the function receive a configuration object which define how the HMAC digest is calculated and return a function to validate the HMAC digest signature for different inputs.

```js
let validate = hmacValidator({
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
  excludedKeys: ['extra'],
  algorithm: 'sha256',
  format: 'hex'
});

let digest = 'c2812f39f84c32c2edaded339a1388abc9829babf351b684ab797f04cd94d4c7';

let isValid = validate(secret, {
  shop: 'some-shop.myshopify.com',
  timestamp: '1337178173',
  extra: '6e39a2ea9e497af6cb806720da1f1bf3'
}, digest);

// isValid is true for this case
```

### Configuration parameters

The module exports a function which accepts an Object with the next configuration parameters:

* `algorithm`: A string which defines the algorithm to use; the algorithms accepted are the same ones offered by NodeJS and accepted by [`crpto.createHmac`](https://nodejs.org/dist/latest-v4.x/docs/api/crypto.html#crypto_crypto_createhmac_algorithm_key).
* `format`: A string which define the format (encoding) to use to generate the signed digest; the supported formats are the same ones that [`hmac.digest` NodeJS method offers](https://nodejs.org/dist/latest-v4.x/docs/api/crypto.html#crypto_hmac_digest_encoding).
* `excludedKeys`: An array of properties names (keys) to exclude from the payload before the signature calculation.
* [`keyValueLink`]: A string to use between the keys and the values of the payload when they are concatenated to generated the message to calculate the signature. Default to `=`;
* [`pairsLink`]: A string to use between the each key and value pair of the payload when they are concatenated to generated the message to calculate the signature. Default to `&`;
* `replacements`: Object with 3 optional properties: `keys`, `values` and `both`.

  The three of them accept __one character property name__ with a string property value; the property name defines the character to replaced by the sting set as property value of the payload (message) to calculate and compare the HMAC digest signature

  The replacements are done on the payload, `key` replace the values only in keys of the payload, `values` on their values and `both` in the both of them.
* [`digestKey`]: The name of the key to find in the payload which contains the original HMAC digest value, which is used to check if the signature is valid, therefore the message is coming from the trusted source. Default to `null`.

After the function is called with the configuration object a new function is returned to validate the signature for different payloads and secrets if you want, although the secret probably doesn't change, because it's used on each call I thought that it offer more flexibility if it's provided on each call than setting it in the configuration object.

The returned function accept 2 or 3 parameters depending if `digestKey` configuration parameter has been set.

When `digestKey` is provided, the function accepts 2 parameters (the secret and payload), the signature to compare the calculated HMAC digest, is self contained in the same payload; the module exclude automatically this key from the payload, so it isn't needed to add in the `excludedKeys` list; otherwise the function requires 3 parameters, those 2 and the signature to compare the calculated HMAC digest.


Check the test specs in the [test folder](https://github.com/ifraixedes/node-hmac-validator/tree/master/test) to see more examples.

## Requirements & dependencies

The module doesn't have any dependency for its usage than the modules provided by NodeJS API.
You need at least NodeJS v4.x as it's implemented with JS2015 (ES6) features, as expected it also works with v5.x; it may work with a previous version which offer the same JS2015 features enabled by a flag, however I haven't bothered to check it.

## Origins, Why? and Current Status

This module was born of one implementation that I had to implement to verify [Shopiphy HMAC Signatures verification](https://docs.shopify.com/api/authentication/oauth) because I wasn't able to find a node module that allowed me to do only the HMAC validation; so I implemented it a bit generic with some of the configurable parameters that it currently offers.

I extracted that first implementation to be and standalone module and publish it on NPM with the goal to provide a generic HMAC Signature validator which can handle most common cases (providers, services, etc... which uses an HMAC signature to guarantee the originator of requests), however, so far, I've only done the generalization that I've prognosticated based on the implementation for Shopify so I guess it may need more changes to be as generic as I desire.

See [Roadmap](#roadmap) for the next steps to check and make changes to achieve more generalization.

## Roadmap

1. Verify if it supports [Twilio Digest Authentication validation](https://www.twilio.com/docs/api/security) writing the needed test cases; if it doesn't pass the new test specs, then make the changes to pass it.
2. Verify if it supports [Twilio Digest Authentication validation](https://www.twilio.com/docs/api/security) writing the needed test cases; if it doesn't pass the new test specs, then make the changes to pass it.

## Development

To develop it, some dependencies are required, you can install them using `npm install`.

Dependencies are:

* [Mocha test framework](https://mochajs.org/)
* [Chai Assertion Library](http://chaijs.com/)
* [ESLint](http://eslint.org/) used to lint all the code in this repo and keep it homogeneous.

## License

MIT, read [LICENSE](https://github.com/ifraixedes/node-hmac-validator/blob/master/LICENSE) file for more information.
