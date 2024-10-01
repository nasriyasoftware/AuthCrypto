class ConfigManager {
    readonly #_helpers = {
        is: {
            validRounds: (r: number) => {
                if (isNaN(r)) { throw new SyntaxError(`The number of rounds in the .env file must be a valid number, instead got ${r}`) }
                if (!Number.isInteger(r)) { throw new SyntaxError('The number of rounds must be a valid number and cannot be less than one') }
                if (r < 1) { throw new RangeError(`The number of rounds cannot be less than one`) }
            }
        }
    }

    /**
     * The number of hashing rounds to use for password hashing.
     * This value is read from the `AuthCrypto_ROUNDS` environment variable.
     * If the value is not a valid number or is less than one, a `SyntaxError` will be thrown.
     * If the value is not set, `undefined` will be returned.
     * @returns {number | undefined} The number of hashing rounds to use.
     */
    get hashingRounds(): number | undefined {
        const rStr = process.env.AuthCrypto_ROUNDS;
        if (!(rStr && typeof rStr === 'string')) { return undefined }

        const r = Number.parseInt(rStr, 10);
        this.#_helpers.is.validRounds(r);
        return r;
    }

    /**
     * Sets the number of hashing rounds for AuthCrypto. This value must be a positive integer of at least 1.
     * @throws {TypeError} If the number of rounds is not a valid number.
     * @throws {RangeError} If the number of rounds is less than 1.
     * @param {number} r The number of hashing rounds to set.
     */
    set hashingRounds(r: number) {
        if (typeof r !== 'number') { throw new TypeError(`The number of rounds must be a number, instead got ${typeof r}`) }
        this.#_helpers.is.validRounds(r);
        process.env.AuthCrypto_ROUNDS = r.toString();
    }

    /**
     * The minimum length of a password for AuthCrypto.
     * This value is read from the `AuthCrypto_PASSWORDS_MIN` environment variable.
     * If the value is not a valid number or is less than 8, a `SyntaxError` or `RangeError` will be thrown.
     * If the value is not set, `undefined` will be returned.
     * @returns {number | undefined} The minimum length of a password.
     */
    get minPasswordLength(): number | undefined {
        const minStr = process.env.AuthCrypto_PASSWORDS_MIN;
        if (minStr === undefined) { return undefined }
        if (!(minStr && typeof minStr === 'string')) { throw new TypeError(`The min password length in the .env file must be a valid number, instead got ${minStr}`) }

        const min = Number.parseInt(minStr, 10);

        if (isNaN(min)) { throw new SyntaxError(`The min password length in the .env file must be a valid number, instead got ${minStr}`) }
        if (!Number.isInteger(min)) { throw new SyntaxError('The min password length must be a valid number and cannot be less than 8') }
        if (min < 8) { throw new RangeError('The min password length cannot be less than 8') }

        return min;
    }

    /**
     * Sets the minimum length of a password for AuthCrypto. This value must be a positive integer of at least 8.
     * @throws {TypeError} If the min password length is not a valid number.
     * @throws {RangeError} If the min password length is less than 8.
     * @param {number} min The minimum length of a password to set.
     */
    set minPasswordLength(min: number) {
        if (!Number.isInteger(min)) { throw new TypeError('The min password length must be a valid number and cannot be less than 8') }
        if (min < 8) { throw new RangeError('The min password length cannot be less than 8') }
        process.env.AuthCrypto_PASSWORDS_MIN = min.toString();
    }


    /**
     * The maximum length of a password for AuthCrypto.
     * This value is read from the `AuthCrypto_PASSWORDS_MAX` environment variable.
     * If the value is not a valid number or is greater than 32, a `SyntaxError` or `RangeError` will be thrown.
     * If the value is not set, `undefined` will be returned.
     * @returns {number | undefined} The maximum length of a password.
     */
    get maxPasswordLength(): number | undefined {
        const maxStr = process.env.AuthCrypto_PASSWORDS_MAX;
        if (maxStr === undefined) { return undefined }
        if (!(maxStr && typeof maxStr === 'string')) { throw new TypeError(`The max password length in the .env file must be a valid number, instead got ${maxStr}`) }

        const max = Number.parseInt(maxStr, 10);

        if (isNaN(max)) { throw new SyntaxError(`The max password length in the .env file must be a valid number, instead got ${maxStr}`) }
        if (!Number.isInteger(max)) { throw new SyntaxError('The max password length must be a valid number and cannot be greater than 32') }
        if (max < 8) { throw new RangeError('The max password length cannot be less than 8') }

        return max;
    }

    /**
     * Sets the maximum length of a password for AuthCrypto. This value must be a positive integer of at most 32.
     * @throws {TypeError} If the max password length is not a valid number.
     * @throws {RangeError} If the max password length is greater than 32.
     * @param {number} max The maximum length of a password to set.
     */
    set maxPasswordLength(max: number) {
        if (!Number.isInteger(max)) { throw new TypeError('The max password length must be a valid number and cannot be greater than 32') }
        if (max < 8) { throw new RangeError('The max password length cannot be less than 8') }
        if (this.minPasswordLength && max < this.minPasswordLength) { throw new RangeError('The max password length cannot be less than the min password length') }
        process.env.AuthCrypto_PASSWORDS_MAX = max.toString();
    }


    /**
     * Returns the secret key used to sign and verify JSON Web Tokens.
     * This value is read from the `AuthCrypto_JWT_SECRET` environment variable.
     * If the value is not a valid string or is not at least 64 bytes long for HS512, a `TypeError` will be thrown.
     * If the value is not set, `undefined` will be returned.
     * @returns {string | undefined} The secret key used for JWT signing and verification.
     */
    get jwtSecret(): string | undefined {
        const secret = process.env.AuthCrypto_JWT_SECRET;
        if (secret === undefined) { return undefined }
        if (typeof secret !== 'string') { throw new TypeError('The JWT secret must be a string') }

        const keyBytes = Buffer.byteLength(secret, 'utf8');
        if (keyBytes < 64) { throw new Error(`The "AuthCrypto_JWT_SECRET" key must be at least 64 bytes long for HS512. Found: ${keyBytes} bytes.`); }

        return secret;
    }

    /**
     * Sets the secret key used to sign and verify JSON Web Tokens.
     * This value must be a string and at least 64 bytes long for HS512.
     * @throws {TypeError} If the JWT secret is not a string.
     * @throws {Error} If the JWT secret is less than 64 bytes long.
     * @param {string} secret The secret key used to sign and verify JSON Web Tokens.
     */
    set jwtSecret(secret: string) {
        if (typeof secret !== 'string') { throw new TypeError('The JWT secret must be a string') }

        const keyBytes = Buffer.byteLength(secret, 'utf8');
        if (keyBytes < 64) { throw new Error(`The "AuthCrypto_SECRET" key must be at least 64 bytes long for HS512. Found: ${keyBytes} bytes.`); }

        process.env.AuthCrypto_SECRET = secret;
    }

    /**
     * Sets the configuration options for AuthCrypto.
     * @param {Configs} configs An object with the configuration options.
     * @throws {TypeError} If the config is not an object.
     * @throws {Error} If any of the required properties are missing from the config object.
     */
    set(configs: Configs) {
        if (configs && typeof configs === 'object' && !Array.isArray(configs) && configs !== null && Object.keys(configs).length > 0) {
            if ('minPasswordLength' in configs) {
                this.minPasswordLength = configs.minPasswordLength;
            }

            if ('maxPasswordLength' in configs) {
                this.maxPasswordLength = configs.maxPasswordLength;
            }

            if ('jwtSecret' in configs) {
                this.jwtSecret = configs.jwtSecret;
            }

            if ('hashingRounds' in configs) {
                this.hashingRounds = configs.hashingRounds;
            }
        } else {
            throw new TypeError('The config must be an object with at least one property')
        }
    }
}

interface Configs {
    minPasswordLength: number;
    maxPasswordLength: number;
    jwtSecret: string;
    hashingRounds: number;
}

export default ConfigManager;