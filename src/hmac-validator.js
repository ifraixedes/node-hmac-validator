'use strict';

let qs = require('querystring');
let crypto = require('crypto');

module.exports = createValidator;

const encoding = 'ascii';

/**
 * Create Validator
 *
 * @param {Object} config - Contains the configuration parameters
 *      All of them are pull out or assigned to default values in the first lines so take a
 *      look which ones are required and accepted
 * @returns {Function} which compute the digest and compare it to return true or false if they match.
 *      Returned function accepts as parameters:
 *         - {string} Secret: the share secret to use to compute the digest
 *         - {string} Prefix: it will be prepended (without any transformation) to the payload before calculating
 *              the digest signature.
 *         - {Object|string} Payload: in case of string it will be parsed with querystrint to transform in an object
 *         - {string} [digest]: Digest to compare, not required if configuration specified `digestKeys` parameter, which
 *              defines the key inside of the object to check which has the digest value
 *  NOTE: Payload is only an object with string value properties.
 */
function createValidator(config) {
  checkConfig(config);

  let algorithm = config.algorithm;
  let format = config.format;
  let excludedKeys = (config.excludedKeys instanceof Set) ? config.excludedKeys : new Set(config.excludedKeys);
  let replacements = (config.replacements) ? compileReplacements(config.replacements) : null;
  let keyValueLink = (typeof config.keyValueLink === 'string') ? config.keyValueLink : '=';
  let pairsLink = (typeof config.pairsLink === 'string') ? config.pairsLink : '&';

  let digestKey = null;

  if (config.digestKey) {
    digestKey = config.digestKey;
    excludedKeys.add(config.digestKey);
  }

  return function (secret, prefix, payload, digest) {
    let message = (prefix) ? prefix : '';

    if (payload) {
      let pobj = payloadToObject(payload);

      if (!digest) {
        if (!digestKey) {
          throw new Error('Digest should be provided because not digest key was set');
        } else {
          digest = pobj[digestKey];
        }
      }

      pobj = removeExcludedKeys(excludedKeys, pobj);

      if (replacements) {
        pobj = makeReplacements(replacements, pobj);
      }

      message += getDigestMessage(pobj, keyValueLink, pairsLink);
    }

    let hmac = crypto.createHmac(algorithm, secret);
    hmac.update(message, encoding);

    return hmac.digest(format) === digest;
  };
}

/**
 * Makes basic checks on Hmac validator configuration like required parameters.
 *
 * @param {Object} config - The configuration used to create a new Hmac validator
 * @throws {Error} When one of the checks fails
 */
function checkConfig(config) {
  let requiredProps = ['algorithm', 'format'];
  const errMsg = `Configuration isn't an object with the required properties: ${requiredProps.join(', ')}`;

  if ((!config) || (typeof config !== 'object')) {
    throw new Error(errMsg);
  }

  requiredProps.forEach(p => {
    if (!config[p]) {
      throw new Error(errMsg);
    }
  });
}

function payloadToObject(p) {
  if (typeof p === 'string') {
    return qs.parse(p, null, null, { maKeys: 0 });
  }

  return p;
}

function removeExcludedKeys(eKeys, obj) {
  let result = {};

  Object.keys(obj).forEach(k => {
    if (eKeys.has(k)) {
      return;
    }

    result[k] = obj[k];
  });

  return result;
}

function makeReplacements(replacements, obj) {
  let result = {};
  let oKeys = Object.keys(obj);
  let rValues = replacements.values;
  let rKeys = replacements.keys;

  for (let key of oKeys) {
    let value = charReplacer(obj[key], rValues);
    key = charReplacer(key, rKeys);
    result[key] = value;
  }

  return result;
}

function charReplacer(str, replChars) {
  let result = '';

  for (let c of str) {
    let rc = replChars.find(pair => pair[0] === c);
    result += rc === undefined ? c : rc[1];
  }

  return result;
}

function compileReplacements(confRepls) {
  let errMsg = 'Invalid replacement: object properties for keys, values & both '
    + 'must be exactly 1 character';
  let keys, values;

  if (confRepls.keys) {
    keys = Object.keys(confRepls.keys).map(k => {
      if (k.length !== 1) {
        throw new Error(errMsg);
      }

      return [k, confRepls.keys[k]];
    });
  }

  if (confRepls.values) {
    values = Object.keys(confRepls.values).map(k => {
      if (k.length !== 1) {
        throw new Error(errMsg);
      }

      return [k, confRepls.values[k]];
    });
  }

  if (confRepls.both) {
    if (!keys) {
      keys = [];
    }

    if (!values) {
      values = [];
    }

    let both = confRepls.both;
    Object.keys(both).forEach(k => {
      if (k.length !== 1) {
        throw new Error(errMsg);
      }

      keys.push([k, both[k]]);
      values.push([k, both[k]]);
    });
  }


  if ((!keys) && (!values)) {
    return null;
  }

  return {
    keys: keys,
    values: values
  };
}

function getDigestMessage(obj, keyValueLink, pairsLink) {
  let sortedKeys = Object.keys(obj).sort();
  let keyVals = [];

  for (let k of sortedKeys) {
    keyVals.push(`${k}${keyValueLink}${obj[k]}`);
  }

  return keyVals.join(pairsLink);
}
