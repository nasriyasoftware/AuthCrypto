[![N|Solid](https://static.wixstatic.com/media/72ffe6_da8d2142d49c42b29c96ba80c8a91a6c~mv2.png)](https://nasriya.net)
# AuthCrypto.
[![Static Badge](https://img.shields.io/badge/license-Free_(Restricted)-blue)](https://github.com/nasriyasoftware/AuthCrypto?tab=License-1-ov-file) ![Repository Size](https://img.shields.io/github/repo-size/nasriyasoftware/AuthCrypto.svg) ![Last Commit](https://img.shields.io/github/last-commit/nasriyasoftware/AuthCrypto.svg) [![Status](https://img.shields.io/badge/Status-Stable-green.svg)](link-to-your-status-page)
##### Visit us at [www.nasriya.net](https://nasriya.net).

**AuthCrypto** is a powerful library for handling cryptographic operations and JWT (JSON Web Tokens) in Node.js applications. It provides utilities for hashing passwords, generating JWT tokens, and more.

Made with ❤️ in **Palestine** 🇵🇸
___
## Features

- **Password Hashing**: Securely hash and verify passwords with support for salts and multiple hashing algorithms.
- **JWT Management**: Easily create and verify JSON Web Tokens for secure authentication.
- **Customizable Options**: Configure hashing and JWT options to fit your application's needs.

___
## Installation

You can install `AuthCrypto` via npm:

```bash
npm install @nasriya/authcrypto
```

Or using yarn:

```bash
yarn add @nasriya/authcrypto
```
___
## Importing
Import in **ESM** module
```ts
import authCrypto from '@nasriya/authcrypto';
```

Import in **CommonJS (CJS)**
```js
const authCrypto = require('@nasriya/authcrypto').default;
```
___

## Configuration

**AuthCrypto** reads configuration values from environment variables:

- `AuthCrypto_ROUNDS`: The number of hashing rounds for password hashing.
- `AuthCrypto_PASSWORDS_MIN`: Minimum length for passwords (default: `8`).
- `AuthCrypto_PASSWORDS_MAX`: Maximum length for passwords (default: `32`).
- `AuthCrypto_SECRET`**`*`**: A secret phrase to generate and verify JWT. Can be generated from [crypto.generateSecret()](#generating-secrets).

You can set these values in your `.env` file:

```env
AuthCrypto_ROUNDS=10
AuthCrypto_PASSWORDS_MIN=8
AuthCrypto_PASSWORDS_MAX=32
AuthCrypto_SECRET=Your_secret
```

> **:warning: Important Note**
> 
> You must specify the `Crypto JWT_SECRET` variable in your environment, otherwise, your system might be at risk of forgery
___

## Usage

### Hashing 

To hash strings, use the `crypto` API:

#### Hashing
```ts
const value = 'Something to hash';
authCrypto.crypto.hash(value);               // ⇨ b633c3e9f63478eb1fd0d311b1c35050644bf39d03e6f138a9ecf9ba2bc44cb77241dc5e08da50acb46053cafd11ac593a34d074d81c6b9b63a38e116ea14cba
authCrypto.crypto.hash(value, 'SHA512');     // ⇨ b633c3e9f63478eb1fd0d311b1c35050644bf39d03e6f138a9ecf9ba2bc44cb77241dc5e08da50acb46053cafd11ac593a34d074d81c6b9b63a38e116ea14cba
authCrypto.crypto.hash(value, 'SHA256');     // ⇨ ff75b3f89087a50f82c5fe8698d65a8ca8b2fdb9ddd698f8d0930b5ff963826d
authCrypto.crypto.hash(value, 'MD5');        // ⇨ b642e7e30f7eb096f02f02384163b1d8
authCrypto.crypto.hash(value, 'SHA1');       // ⇨ 2d7cb72b42172a3cb55b1db09fb4d96fcad14563
```

#### Generating Salt
```ts
// A 512-char salt
authCrypto.crypto.generateSalt();
// ⇨ a05c9ae0c36e82a09e4fb947c744701f498069816af016a0b6c233a3291cecaa3e1b12d7059a1eac93ea828aedb94de13347c50610e06514f495f9989f0182f1b2e283a4f95d61691784a77576f7e5f5318030707146a5547aca0ef9177eb996ef21f9be20c4f4a82ad8191d35c46a4d24f6c0460f7a025eb41c0ef6388f8fe79ea5b393c28b719734a842982bdd750e66ae84d74feea21b7ebfc8ba2a507011bffe54c2ebe7e09e529724ad49fc6623617f025a5acb8edc45348483471f5e5d97b7f7d93cc13aba90589be64b015faea678212ee61c40946c279c6436c5103cbe7805d09bd455005fbe08b4651c61f04d69d3299fcdcfc64b7f2293006b571d

// A 32-char salt
authCrypto.crypto.generateSalt(32);
// ⇨ a89cd25cc53ff2819e4916a54fffd474
```

#### Hashing + Salt
```ts
const value = 'Something to hash';
const salt = authCrypto.crypto.generateSalt(8);

authCrypto.crypto.hash(value, salt);               // ⇨ 120294cb8e1a5f03a6204b2aa86d2a6c4ad7484eb97d550dda7e9bef61ff7bf68f26f2155d057f477857aaff2a2da5d40e1492a314958185ab3f1cf064763fee
authCrypto.crypto.hash(value, salt, 'SHA512');     // ⇨ 120294cb8e1a5f03a6204b2aa86d2a6c4ad7484eb97d550dda7e9bef61ff7bf68f26f2155d057f477857aaff2a2da5d40e1492a314958185ab3f1cf064763fee
authCrypto.crypto.hash(value, salt, 'SHA256');     // ⇨ 5607d5a6eabd064c30f582966df3c303fcd81731efbc548014267d58426abc1f
authCrypto.crypto.hash(value, salt, 'MD5');        // ⇨ 7ad52f0862c310a186138681524eadc3
authCrypto.crypto.hash(value, salt, 'SHA1');       // ⇨ ea8971d4fc8bf334bed9d5799314c62fb7337eb7
```

#### Generating Secrets
You can generate **64 bytes** (512 bit) secret keys using the **crypto** module.

```ts
authCrypto.crypto.generateSecret()
// ⇨ b7f8de80f54fb1e95597497fd19ff05319d02e6ebc4a0a762e291dbfa650ed05cdf226dfdbfa59a6059815333465c4303888cea666a1f75d9492a30773b2017c
```

### Passwords
The `Passwords` module provides functionality for generating and verifying passwords with configurable options. Here's a detailed explanation of its features and how to use them.

#### 1. Generating a Random Password
The `generate` method creates a random password based on the specified `length` and `options`.

Example Usage:
```ts
const password = authCrypto.passwords.generate(32, {
    includeNumbers: true,
    includeLetters: true,
    includeSymbols: true,
    beginWithLetter: true,
    noSimilarChars: true,
    noDuplicateChars: true,
    noSequentialChars: true
});

console.log(password);  // ⇨ ysYT"2U=Ekx|?}G!K{9#NIHP4d'fQ.b8
```

Explanation:

- `length`: The length of the password, which must be between 8 and 32 characters.
- `options`: An object to configure password generation:
    - `includeNumbers`: Whether to include numbers in the password.
    - `includeLetters`: Whether to include letters in the password.
    - `includeSymbols`: Whether to include symbols in the password.
    - `beginWithLetter`: If true, the password will start with a letter.
    - `noSimilarChars`: If true, avoids similar characters like 'i', 'l', '1', 'O'.
    - `noDuplicateChars`: If true, avoids duplicate characters in the password.
    - `noSequentialChars`: If true, avoids sequential characters.

#### 2. Verifying a Password
The `verify` method checks if a provided password matches a previously hashed password.

Example Usage:
```ts
const plainPassword = 'mySecretPassword';
const hashedPassword = 'hashedPasswordFromDatabase'; // Assume this is a valid hashed password

const isMatch = Passwords.verify(plainPassword, hashedPassword);

console.log(isMatch); // ⇨ true if the password matches, otherwise false
```

Example Usage with **salting**:
```ts
const plainPassword = 'mySecretPassword';
const hashedPassword = 'hashedPasswordFromDatabase'; // Assume this is a valid hashed password
const salt = 'optionalSalt'; // If a salt was used during hashing

const isMatch = Passwords.verify(plainPassword, hashedPassword, salt);

console.log(isMatch); // ⇨ true if the password matches, otherwise false
```

Explanation:

- `password`: The plain text password to be verified.
- `hashedPassword`: The previously hashed password to compare against.
- `salt`: An optional salt that may have been used in the hashing process.

Validation:
- Ensures that the minimum length is not greater than the maximum length.
- Throws errors if the provided lengths are invalid or if they do not meet the required constraints.

### Generating & Verifying JWT
The `JWTManager` module provides functionality for generating and verifying JSON Web Tokens (JWTs). It uses HMAC with the SHA-512 hash algorithm for signing tokens and offers robust methods for handling JWT operations.

#### 1. Generating a JWT
The `generate` method creates a JWT token by encoding the header and payload, and then signing the token with a secret key.

Example Usage:
```ts
const token = authCrypto.jwt.generate({
    iss: 'auth.domain.com',
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, // 24 hours from now or any time you want
    userid: 'a user id',
    sessionId: 'a session id',
    roles: ['user']
});

console.log(token); // Outputs the generated JWT token
```

Explanation:
- `payload`: An object containing the claims you want to include in the JWT.
    - `iat` (issued at): Automatically set to the current time.
    - `exp` (expiration): Optional. If not provided, defaults to 24 hours from the current time.
    - `iss` (issuer): Optional. If not provided, defaults to 'auth.nasriya.net'.

Validation:
- `exp` must be a number and should be at least 5 minutes in the future if provided.
- `iss` must be a non-empty string if provided.

### 2. Verifying a JWT
The `verify` method checks the validity of a JWT token, including verifying its signature and expiration.

Example Usage:
```ts
const token = 'your.jwt.token'; // Replace with an actual JWT token

const result = authCrypto.jwt.verify(token);

if (result.valid) {
    console.log('Token is valid:', result.payload);
} else {
    throw new Error(result.message);
}
```

Explanation:
- `token`: The JWT token to verify. It must be in the format `header.payload.signature`.
- Returns: An object indicating the result of the verification:
    - `valid`: `true` if the token is valid, `false` otherwise.
    - `payload`: The decoded payload if the token is **valid**.
    - `message`: A description of why the token is **invalid**, if applicable.

___
## License
Please read the license from [here](https://github.com/nasriyasoftware/AuthCrypto?tab=License-1-ov-file).