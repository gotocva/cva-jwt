/*
 * cva-jwt
 *
 * JSON Web Token encode and decode module for Node.js
 *
 * Copyright(c) 2024 Sivabharathy <gotocva@gmail.com> https://sivabharathy.in
 * MIT Licensed
 */

/**
 * Module dependencies
 */
const crypto = require('crypto');

/**
 * Supported algorithm mapping
 */
const algorithmMap = {
  HS256: 'sha256',
  HS384: 'sha384',
  HS512: 'sha512',
  RS256: 'RSA-SHA256'
};

/**
 * Map algorithm to HMAC or sign type, to determine which crypto function to use
 */
const typeMap = {
  HS256: 'hmac',
  HS384: 'hmac',
  HS512: 'hmac',
  RS256: 'sign'
};

/**
 * Expose object
 */
const jwt = module.exports;

/**
 * Version
 */
jwt.version = '0.5.6';

/**
 * Decode JWT
 *
 * @param {String} token
 * @param {String} key
 * @param {Boolean} [noVerify]
 * @param {String} [algorithm]
 * @return {Object} payload
 * @api public
 */
jwt.decode = function decode(token, key, noVerify, algorithm) {
  if (!token) {
    throw new Error('No token supplied');
  }

  const segments = token.split('.');
  if (segments.length !== 3) {
    throw new Error('Invalid token: Not enough or too many segments');
  }

  const [headerSeg, payloadSeg, signatureSeg] = segments;

  // Base64 decode and parse JSON
  const header = JSON.parse(base64urlDecode(headerSeg));
  const payload = JSON.parse(base64urlDecode(payloadSeg));

  if (!noVerify) {
    if (!algorithm && /BEGIN( RSA)? PUBLIC KEY/.test(key.toString())) {
      algorithm = 'RS256';
    }

    const signingMethod = algorithmMap[algorithm || header.alg];
    const signingType = typeMap[algorithm || header.alg];
    if (!signingMethod || !signingType) {
      throw new Error('Algorithm not supported');
    }

    // Verify signature
    const signingInput = [headerSeg, payloadSeg].join('.');
    if (!verify(signingInput, key, signingMethod, signingType, signatureSeg)) {
      throw new Error('Signature verification failed');
    }

    // Support for nbf and exp claims
    if (payload.nbf && Date.now() < payload.nbf * 1000) {
      throw new Error('Token not yet active');
    }

    if (payload.exp && Date.now() > payload.exp * 1000) {
      throw new Error('Token expired');
    }
  }

  return payload;
};

/**
 * Encode JWT
 *
 * @param {Object} payload
 * @param {String} key
 * @param {String} [algorithm='HS256']
 * @param {Object} options
 * @return {String} token
 * @api public
 */
jwt.encode = function encode(payload, key, algorithm = 'HS256', options) {
  if (!key) {
    throw new Error('Key is required');
  }

  const signingMethod = algorithmMap[algorithm];
  const signingType = typeMap[algorithm];
  if (!signingMethod || !signingType) {
    throw new Error('Algorithm not supported');
  }

  // Header, typ is fixed value
  const header = { typ: 'JWT', alg: algorithm };
  if (options && options.header) {
    Object.assign(header, options.header);
  }

  // Create segments, all segments should be base64 strings
  const headerSegment = base64urlEncode(JSON.stringify(header));
  const payloadSegment = base64urlEncode(JSON.stringify(payload));
  const signingInput = `${headerSegment}.${payloadSegment}`;
  const signatureSegment = sign(signingInput, key, signingMethod, signingType);

  return `${headerSegment}.${payloadSegment}.${signatureSegment}`;
};

/**
 * Private utility functions
 */
function verify(input, key, method, type, signature) {
  if (type === 'hmac') {
    return signature === sign(input, key, method, type);
  } else if (type === 'sign') {
    return crypto.createVerify(method)
      .update(input)
      .verify(key, base64urlUnescape(signature), 'base64');
  }
  throw new Error('Algorithm type not recognized');
}

function sign(input, key, method, type) {
  let base64str;
  if (type === 'hmac') {
    base64str = crypto.createHmac(method, key).update(input).digest('base64');
  } else if (type === 'sign') {
    base64str = crypto.createSign(method).update(input).sign(key, 'base64');
  } else {
    throw new Error('Algorithm type not recognized');
  }

  return base64urlEscape(base64str);
}

function base64urlDecode(str) {
  return Buffer.from(base64urlUnescape(str), 'base64').toString();
}

function base64urlUnescape(str) {
  str += '='.repeat((4 - str.length % 4) % 4);
  return str.replace(/-/g, '+').replace(/_/g, '/');
}

function base64urlEncode(str) {
  return base64urlEscape(Buffer.from(str).toString('base64'));
}

function base64urlEscape(str) {
  return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
