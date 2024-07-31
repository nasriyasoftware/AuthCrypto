import crypto from './assets/crypto/crypto';
import jwt from './assets/jwt/jwt';
import passwords from './assets/passwords/passwords';

/**
 * AuthCrypto is the main entry point for the AuthCrypto package.
 * It provides access to crypto utilities, JWT handling, and password management.
 */
class AuthCrypto {
    /**Crypto utilities for hashing and other cryptographic operations. */
    readonly crypto = crypto;
    /**JWT handling utilities for encoding and decoding JSON Web Tokens. */
    readonly jwt = jwt;
    /**Password management utilities for generating and verifying passwords. */
    readonly passwords = passwords
}

const authCrypto = new AuthCrypto();
export default authCrypto;