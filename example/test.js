const jwt = require('../index');


console.log(jwt);

let payload = { foo: 'bar' };
let secret = 'xxx';

// HS256 secrets are typically 128-bit random strings, for example hex-encoded:
// let secret = Buffer.from('fe1a1915a379f3be5394b64d14794932', 'hex')

// encode
let token = jwt.encode(payload, secret);

console.log('Encoded token', token);

// decode
let decoded = jwt.decode(token, secret);
console.log(decoded); //=> { foo: 'bar' }

