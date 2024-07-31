import crypto from 'crypto';
import hashing from '../crypto/crypto';
import { RandomOptions } from "../../docs/docs";

class Passwords {
    readonly #_config = {
        minLength: 8,
        maxLength: 32,
    }

    readonly #_cosntants = {
        numbers: '0123456789',
        lowercaseLetters: 'abcdefghijklmnopqrstuvwxyz',
        uppercaseLetters: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        symbols: '!";#$%&\'()*+,-./:;<=>?@[]^_`{|}~',
    }

    readonly #_helpers = {
        padToLength: (value: string, targetLength: number): string => {
            if (value.length >= targetLength) {
                return value;
            }
            return value.padEnd(targetLength, ' '); // Pad with spaces
        }
    }

    constructor() {
        const minStr = process.env.AuthCrypto_PASSWORDS_MIN;
        const maxStr = process.env.AuthCrypto_PASSWORDS_MAX;

        if (minStr) {
            if (typeof minStr !== 'string') {
                throw new TypeError('AuthCrypto_PASSWORDS_MIN must be a string.');
            }

            const minLength = Number.parseInt(minStr, 10);

            if (isNaN(minLength) || minLength < 8) {
                throw new RangeError('AuthCrypto_PASSWORDS_MIN must be a positive integer of at least 8.');
            }

            this.#_config.minLength = minLength;
        }

        if (maxStr) {
            if (typeof maxStr !== 'string') {
                throw new TypeError('AuthCrypto_PASSWORDS_MAX must be a string.');
            }

            const maxLength = Number.parseInt(maxStr, 10);

            if (isNaN(maxLength) || maxLength > 32) {
                throw new RangeError('AuthCrypto_PASSWORDS_MAX must be a positive integer not greater than 32.');
            }

            this.#_config.maxLength = maxLength;
        }

        // Ensure minLength is less than or equal to maxLength
        if (this.#_config.minLength > this.#_config.maxLength) {
            throw new RangeError(`AuthCrypto's minimum value ${this.#_config.minLength} cannot be greater than the maximum value ${this.#_config.maxLength}`);
        }
    }

    /**
     * Generate a random password
     * @param length The length of the password. Min of `8` and Max of `32`
     * @param [options] Options for generating the password
     * @returns {string} Generated password
     * @throws {RangeError} If length is outside of the specified range
     */
    generate(length: number, options: RandomOptions = {}): string {
        if (length < this.#_config.minLength || length > this.#_config.maxLength) {
            throw new RangeError('Password length must be between 8 and 32 characters.');
        }

        const {
            includeNumbers = true,
            includeLetters = true,
            includeSymbols = true,
            includeLowerCaseChars = true,
            includeUpperCaseChars = true,
            beginWithLetter = true,
            noSimilarChars = true,
            noDuplicateChars = false,
            noSequentialChars = true
        } = options;

        let chars = '';
        let text = '';

        if (includeNumbers) chars += this.#_cosntants.numbers;
        if (includeLetters) {
            if (includeLowerCaseChars) chars += this.#_cosntants.lowercaseLetters;
            if (includeUpperCaseChars) chars += this.#_cosntants.uppercaseLetters;
        }

        if (includeSymbols) chars += this.#_cosntants.symbols;

        if (chars.length === 0) {
            throw new Error('No characters available for generating password.');
        }

        if (beginWithLetter) {
            const letters = (includeLowerCaseChars ? this.#_cosntants.lowercaseLetters : '') + (includeUpperCaseChars ? this.#_cosntants.uppercaseLetters : '');
            if (letters.length > 0) {
                text += letters.charAt(crypto.randomInt(letters.length));
            } else {
                // If no letters are included, just add a random character from the pool
                text += chars.charAt(crypto.randomInt(chars.length));
            }

            // Reduce the length by one as we've already added the starting character
            length--;
        }

        while (text.length < length) {
            const randomIndex = crypto.randomInt(chars.length);
            const char = chars[randomIndex];

            if (
                (noSimilarChars && /[il1LoO]/.test(char)) ||
                (noDuplicateChars && text.includes(char)) ||
                (noSequentialChars && text.length > 0 && text[text.length - 1].charCodeAt(0) + 1 === char.charCodeAt(0))
            ) {
                continue;
            }

            text += char;
        }

        return text;
    }


    /**
     * Verifies if the provided password matches the hashed password.
     * 
     * @param password - The plain password to verify.
     * @param hashedPassword - The previously hashed password to compare against.
     * @param salt - An optional salt to use for hashing the password.
     * @returns {boolean} True if the password matches the hashed password, otherwise false.
     * @throws {TypeError} If password or hashedPassword is not a string.
     * @throws {Error} If the hashedPassword is not in the expected format.
     */
    verify(password: string, hashedPassword: string, salt?: string): boolean {
        if (typeof password !== 'string') {
            throw new TypeError('The password must be a string.');
        }

        if (typeof hashedPassword !== 'string') {
            throw new TypeError('The hashed password must be a string.');
        }

        if (salt !== undefined && typeof salt !== 'string') {
            throw new TypeError('The salt must be a string if provided.');
        }

        // Combine the password and salt (if provided) and hash it
        const inputToHash = salt ? password + salt : password;
        const hashedInput = hashing.hash(inputToHash);

        // Specify a random length
        const maxLength = Math.max(hashedInput.length, hashedPassword.length) + crypto.randomInt(50);

        // Pad both hashed values to the max length
        const paddedInput = this.#_helpers.padToLength(hashedInput, maxLength);
        const paddedPassword = this.#_helpers.padToLength(hashedPassword, maxLength);

        // Compare the newly hashed value with the provided hashed password
        let isMatched = true;
        for (let i = 0; i < maxLength; i++) {
            isMatched = isMatched && (paddedInput[i] === paddedPassword[i]);
        }

        return isMatched;
    }
}

export default new Passwords();