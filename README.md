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

let isValid = validate(secret, null, {
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
* [`digestKey`]: The name of the key to find in the payload which contains the original HMAC digest value, which is used to check if the signature is valid, therefore the message is coming from the trusted source. For obvious reasons, if the payload self contains the digest Key, it will be automatically excluded from it, before calculating the digest, so it isn't needed to be added to `excludedKeys` list. Default to `null`.

After the function is called, a [validator function](#validator-function) is returned.

### Validator function

Validator function allow to validate the signature for different payloads and secrets, [applying the specified configuration which has created it](#configuration-parameters).

The returned function accept 3 or 4 parameters depending if `digestKey` configuration parameter has been set.

When `digestKey` is provided, the function accepts 3 parameters (the secret, prefix, and payload), the signature to compare the calculated HMAC digest, is self contained in the same payload (specified by `digestKey` configuration parameter); otherwise the function requires 4 parameters, those 3 and the signature to compare the calculated HMAC digest.

The __prefix is a string which is prepended to the payload after it has been processed and before the HMAC signature is computed to be validated__; some providers need a prefix and others don't; for example there are providers as [Twilio](https://www.twilio.com/docs/api/security) which calculate the signatures using the full URL concatenated with the request body with some processing, in this module, the full URL is prefix and the body is the payload and others, as [Shopify](https://docs.shopify.com/api/guides/authentication/oauth), which only use the URL parameters as the payload and anything more, so it doesn't need any prefix.

If the provider doesn't need prefix, provide a `null` or empty `string`.

The __payload__ can be:

* A String: the value should be a valid query string (it's parsed with `querystring` NodeJS API module).
* An Object: use as a map (key / value); both are converted to Javascript strings, so if some of them isn't one of [the types](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Data_structures#Data_types) whose string representation matches your expectations, then you should have to override `toString` method, for example if you have keys with an Object value.

As the prefix, if it isn't required, provide a `null` value or empty `string`;

On the other hand you may notice that the `secret` isn't probably to change during the functions life, so it could be set as a configuration parameter, however I thought that providing it, as a parameter on each call, has more flexibility, allowing to change it without creating a new validator function; The difference, between `secret` and all the configuration parameters, is that consumers can generate one at any time, meanwhile the configurations parameters values are totally defined by the provider.

### Examples

You can find 3 examples, written as mocha test cases which try to show the related part to calculate the signature for [Shopify](https://docs.shopify.com/api/guides/authentication/oauth), [Twilio](https://www.twilio.com/docs/api/security) and [Pusher](https://pusher.com/docs/auth_signatures), on [examples-test.js file](https://github.com/ifraixedes/node-hmac-validator/blob/master/test/examples-test.js).

### Other considerations

The exported function does a few checks on the configuration object, however they aren't bulletproof and I don't plan to do it, having to full check each types of any configuration parameter and value; I added some to may help to detect basic misconfigurations which can lead to waste time trying to spot a misusage of this module in the library or application which uses this module.

The same happens with the returned function, but on it there is another __minimal consideration__, performance; as it's probably a function that the library or application which uses this module, will call it over and over.

Basically I expect that who uses this module, will read the documentation and use it as it's defined.

You can see those checks in the file [src/hmac-validator.js](https://github.com/ifraixedes/node-hmac-validator/blob/master/src/hmac-validator.js) in two functions, `checkConfig` which check the configuration object and `compileReplacements` which transforms, and at the same time check, the `replacements` configuration parameters in the internal data structure used by the returned HMAC validator function.

Check the test specs in the [test folder](https://github.com/ifraixedes/node-hmac-validator/tree/master/test) to see more examples.

On the other hand, some providers don't need almost any of the features offered by this module, even though it can be used, I don't see any benefit in using it if you app only need to verify one provider or several with the same conditions, because the verification carried by this modules is just:

```js
const crypto = require('crypto');

// `payload` is a string with the content to calculate the HMAC digest signature
// and `digest` the signature to verify (compare)
let hmac = crypto.createHmac(algorithm, secret);
hmac.update(payload, encoding);

const isValid = hmac.digest(format) === digest;
```

An example of this case is [Pusher](https://pusher.com/docs/auth_signatures), [there is an example of using this module to verify a Pusher signature](https://github.com/ifraixedes/node-hmac-validator/blob/master/test/examples-test.js#L89) however as I mentioned isn't worthwhile to use if you need to perform Pusher signature verifications.


## Requirements & dependencies

The module doesn't have any dependency for its usage than the modules provided by NodeJS API.
You need at least NodeJS v4.x as it's implemented with JS2015 (ES6) features, as expected it also works with v5.x; it may work with a previous version which offer the same JS2015 features enabled by a flag, however I haven't bothered to check it.

## Origins, Why? and Current Status

This module was born of one implementation that I had to implement to verify [Shopiphy HMAC Signatures verification](https://docs.shopify.com/api/authentication/oauth) because I wasn't able to find a node module that allowed me to do only the HMAC validation; so I implemented it a bit generic with some of the configurable parameters that it currently offers.

I extracted that first implementation to be and standalone module and publish it on NPM with the goal to provide a generic HMAC Signature validator which can handle most common cases (providers, services, etc... which uses an HMAC signature to guarantee the originator of requests).

So far there are a few examples of verifying the signature with some providers, but I'm willing to know if somebody has tried to use for others and know if it is useful.

## Roadmap

1. Deprecate `replacements.both` and only use `keys` & `values`; if a character must be replaced in both, then set it in the two of them; it's simpler and clearer.
2. Look for other providers and write an example in [examples-test.js file](https://github.com/ifraixedes/node-hmac-validator/blob/master/test/examples-test.js).

## Development

To develop it, some dependencies are required, you can install them using `npm install`.

Dependencies are:

* [Mocha test framework](https://mochajs.org/)
* [Chai Assertion Library](http://chaijs.com/)
* [ESLint](http://eslint.org/) used to lint all the code in this repo and keep it homogeneous.

## License

MIT, read [LICENSE](https://github.com/ifraixedes/node-hmac-validator/blob/master/LICENSE) file for more information.
