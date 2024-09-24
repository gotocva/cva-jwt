
```markdown
# CVA JWT

CVA JWT is a simple JSON Web Token (JWT) encode and decode module for Node.js. It allows you to create and verify JWTs using various algorithms.
```

## Installation

You can install the `cva-jwt` package using npm:

```bash
npm install cva-jwt
```

## Usage

### Encoding a JWT

To encode a JWT, use the `encode` method. You'll need to provide a payload, a secret key, and optionally, an algorithm.

```javascript
const jwt = require('cva-jwt');

// Define your payload
const payload = {
  userId: 123,
  role: 'admin'
};

// Define your secret key
const secretKey = 'your-256-bit-secret';


// Encode the token
const token = jwt.encode(payload, secretKey, 'HS256');

console.log('Encoded JWT:', token);
```

HS256 secrets are typically 128-bit random strings, for example hex-encoded:
```javascript
let secret = Buffer.from('fe1a1915a379f3be5394b64d14794932', 'hex')
```

### Decoding a JWT

To decode and verify a JWT, use the `decode` method. You will need to provide the token and the secret key.

```javascript
const token = 'your.jwt.token.here';

try {
  const decodedPayload = jwt.decode(token, secretKey);
  console.log('Decoded Payload:', decodedPayload);
} catch (error) {
  console.error('Error decoding token:', error.message);
}
```

### Options

The `encode` function accepts an optional `options` parameter, which allows you to customize the JWT header.

```javascript
const options = {
  header: {
    kid: 'your-key-id' // Optional key ID
  }
};

const token = jwt.encode(payload, secretKey, 'HS256', options);
```

### Supported Algorithms

- `HS256` (HMAC using SHA-256)
- `HS384` (HMAC using SHA-384)
- `HS512` (HMAC using SHA-512)
- `RS256` (RSA Signature with SHA-256)

### Error Handling

When decoding a JWT, several errors may be thrown:
- `No token supplied`: If no token is provided.
- `Invalid token: Not enough or too many segments`: If the token does not contain exactly three segments.
- `Signature verification failed`: If the signature does not match.
- `Token not yet active`: If the token's `nbf` (not before) claim is not met.
- `Token expired`: If the token's `exp` (expiration) claim has passed.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any enhancements or fixes.

```

### Notes:
- Feel free to customize the content to better match your project's specifics.
- Make sure to include any additional details relevant to your implementation or usage.