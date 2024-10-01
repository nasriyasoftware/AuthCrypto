import CryptoManager from './assets/crypto/crypto';
import JWTManager from './assets/jwt/jwt';
import Passwords from './assets/passwords/passwords';
import ConfigManager from './assets/config/config';

/**
 * AuthCrypto is the main entry point for the AuthCrypto package.
 * It provides access to crypto utilities, JWT handling, and password management.
 */
class AuthCrypto {
    readonly #_authConfigs: ConfigManager;
    readonly #_passwords: Passwords;
    readonly #_jwt: JWTManager;
    readonly #_crypto: CryptoManager;

    constructor() {
        this.#_authConfigs = new ConfigManager();
        this.#_passwords = new Passwords(this.#_authConfigs);
        this.#_jwt = new JWTManager(this.#_authConfigs);
        this.#_crypto = new CryptoManager(this.#_authConfigs);
    }

    /**Crypto utilities for hashing and other cryptographic operations. */
    get crypto() { return this.#_crypto; }

    /**JWT handling utilities for encoding and decoding JSON Web Tokens. */
    get jwt() { return this.#_jwt; }

    /**Password management utilities for generating and verifying passwords. */
    get passwords() { return this.#_passwords; }

    /**Configuration management utilities. */
    get config() { return this.#_authConfigs; }
}

/**
 * authCrypto is the main entry point for the AuthCrypto package.
 * It provides access to crypto utilities, JWT handling, and password management.
 */
const authCrypto = new AuthCrypto();
export default authCrypto;