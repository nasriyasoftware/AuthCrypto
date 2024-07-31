import crypto from 'crypto';
import { InvalidJWTVerification, JwtPayloadCreation, ValidJWTVerification } from '../../docs/docs';

class JWTManager {
    readonly #_headerEncoded: string;
    readonly #_defaultSecret = '69c2f24212965a25149358f4b12cb812a360d3031ede81d5428497ecdaf83ddec083572f38ca28134f13aba75d6af4e7d65f28508cb7cdbac19f667e7cac206f';
    readonly #_secret: string;

    constructor() {
        // Set the header
        const header = {
            alg: "HS512", // HMAC using SHA-512 hash algorithm
            typ: "JWT" // Token type
        };

        this.#_headerEncoded = this.#_helpers.base64urlEncode(JSON.stringify(header));

        const secret = process.env.AuthCrypto_SECRET || this.#_defaultSecret;
        if (!secret) { throw new Error('The JWT Secret is not defined in the process environment.') }

        const keyBytes = Buffer.byteLength(secret, 'utf8');
        if (keyBytes < 64) { throw new Error(`The key must be at least 64 bytes long for HS512. Found: ${keyBytes} bytes.`); }

        this.#_secret = secret;
    }

    readonly #_helpers = Object.freeze({
        /**
         * Convert `base64` string to be compatible with URLs
         * @param base64 A `base64` string to convert
         * @returns {string} The URL encoded base64
         */
        base64ToUrlEncoded: (base64: string): string => {
            return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        },
        /**
         * Convert a plain string into `base64` string
         * @param str A string to convert into `base64`.
         * @returns {string} The `base64` encoded string
         */
        stringToBase64Encode: (str: string): string => {
            return Buffer.from(str).toString('base64');
        },
        /**
         * Convert a string into a `base64` URL encoded string
         * @param str The string you want to encode into `base64` URL
         * @returns {string} The `base64` URL encoded string
         */
        base64urlEncode: (str: string): string => {
            const base64 = this.#_helpers.stringToBase64Encode(str);
            return this.#_helpers.base64ToUrlEncoded(base64);
        },
        createSignature: (message: string) => {
            return crypto.createHmac('sha512', this.#_secret).update(message).digest('base64');
        }
    })

    /**
     * Generates a JWT (JSON Web Token) from a given payload.
     * 
     * This method creates a JWT token by encoding the header and payload using base64 encoding, 
     * and then creating a signature with a secret key. The token is assembled in the format: 
     * `{header}.{payload}.{signature}`.
     * * @example
     * const token = authCrypto.jwt.generate({
     *      iss: 'auth.nasriya.net',
     *      exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24  // 24 hours from now in seconds
     * })
     * @param payload The payload to include in the JWT. This must be an object that can be serialized to JSON.
     * @returns {string} The generated JWT token.
     * @throws {TypeError} If payload is not an object or is null.
     * @throws {Error} If the payload contains invalid or unexpected data.
     */
    generate(payload: JwtPayloadCreation): string {
        // Validate that payload is an object and not null
        if (typeof payload !== 'object' || payload === null) {
            throw new TypeError('The payload must be a non-null object.');
        }

        // Set issued at time (iat)
        payload.iat = Math.floor(Date.now() / 1000);

        // Validate and set expiration (exp)
        if ('exp' in payload) {
            if (typeof payload.exp !== 'number') {
                throw new Error('The `exp` value must be a number.');
            }

            if (payload.exp <= payload.iat) {
                throw new Error('The `exp` value must be in the future.');
            }

            if (payload.exp < payload.iat + (60 * 5)) {
                throw new Error('The `exp` value must be at least 5 minutes in the future.');
            }
        } else {
            payload.exp = payload.iat + (60 * 60 * 24) // 24 hours from now
        }

        // Validate and set issuer (iss)
        if ('iss' in payload) {
            if (typeof payload.iss !== 'string' || payload.iss.trim().length === 0) {
                throw new Error('The `iss` value must be a non-empty string.');
            }
        } else {
            payload.iss = 'auth.nasriya.net'; // Default value
        }

        // Encode the payload
        const headerEncoded = this.#_headerEncoded;
        const payloadEncoded = this.#_helpers.base64urlEncode(JSON.stringify(payload));

        // Create the signature using the secret and encoded header/payload
        const signature = this.#_helpers.createSignature(`${headerEncoded}.${payloadEncoded}`);
        const base64Signature = this.#_helpers.base64ToUrlEncoded(signature);

        // Create the JWT token by concatenating the encoded header/payload/signature
        const token = `${headerEncoded}.${payloadEncoded}.${base64Signature}`;

        return token;
    }

    /**
     * Verifies the validity of a given JWT token.
     * 
     * This method checks if the token's signature is valid and if the token has expired. 
     * It returns an object indicating whether the token is valid or not, along with an 
     * optional message and the decoded payload if valid.
     * 
     * @param token - The JWT token to verify. It must be in the format: `JWT.{header}.{payload}.{signature}`.
     * @returns {ValidJWTVerification | InvalidJWTVerification} An object indicating the result 
     * of the verification:
     * - `valid` (boolean): `true` if the token is valid, `false` otherwise.
     * - `payload` (optional): The decoded payload if the token is valid.
     * - `message` (optional): A description of why the token is invalid, if applicable.
     */
    verify(token: string): ValidJWTVerification | InvalidJWTVerification {
        // Split the token into header/payload/signature
        const parts = token.split(".");
        if (parts.length !== 3) {
            return { valid: false, message: "Invalid token format" };
        }

        const [headerEncoded, payloadEncoded, signature] = parts;

        // Verify the signature
        const expectedSignature = this.#_helpers.createSignature(`${headerEncoded}.${payloadEncoded}`);
        if (signature !== this.#_helpers.base64ToUrlEncoded(expectedSignature)) {
            return { valid: false, message: "Invalid token signature" };
        }

        // Decode the header/payload
        const header = JSON.parse(Buffer.from(headerEncoded, 'base64').toString());
        const payload = JSON.parse(Buffer.from(payloadEncoded, 'base64').toString());

        if ('exp' in payload) {
            if (typeof payload.exp === 'string' && payload.exp.endsWith('Z')) {
                let expiryDate: Date;

                try {
                    expiryDate = new Date(payload.exp);
                    const now = new Date();
                    if (expiryDate <= now) {
                        return { valid: false, message: "The token is expired" };
                    }
                } catch {
                    return { valid: false, message: "Invalid expiry date value" };
                }
            }
        } else {
            return { valid: false, message: "The token is missing the 'exp` property" };
        }

        // Return the payload if the token is valid
        return { valid: true, payload }
    }
}

export default new JWTManager;