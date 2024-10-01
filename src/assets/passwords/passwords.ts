import crypto from 'crypto';
import CryptoManager from '../crypto/crypto';
import { HashAlgorithm, PasswordVerificationOptions, RandomOptions } from "../../docs/docs";
import ConfigManager from '../config/config';

class Passwords {
    readonly #_configManager: ConfigManager;
    readonly #_hashing: CryptoManager;
    readonly #_supportedAlgorithms: HashAlgorithm[] = ['SHA256', 'SHA512', 'MD5', 'SHA1'];

    readonly #_defaults = {
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
        },
        isPasswordVerificationOptions: (options: any): options is PasswordVerificationOptions => {
            return options && typeof options === 'object' && ('algorithm' in options || 'salt' in options);
        }
    }

    get #_maxPasswordLength(): number {
        return this.#_configManager.maxPasswordLength || this.#_defaults.maxLength;
    }

    get #_minPasswordLength(): number {
        return this.#_configManager.minPasswordLength || this.#_defaults.minLength;
    }

    constructor(configManager: ConfigManager) {
        this.#_configManager = configManager;
        this.#_hashing = new CryptoManager(this.#_configManager);
    }

    /**
     * Generate a random password
     * @param length The length of the password. Min of `8` and Max of `32`
     * @param [options] Options for generating the password
     * @returns {string} Generated password
     * @throws {RangeError} If length is outside of the specified range
     */
    generate(length: number, options: RandomOptions = {}): string {
        const minLength = this.#_minPasswordLength;
        const maxLength = this.#_maxPasswordLength;

        if (length < minLength || length > maxLength) {
            throw new RangeError(`Password length must be between ${minLength} and ${maxLength} characters.`);
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
    verify(password: string, hashedPassword: string, options: PasswordVerificationOptions = { algorithm: 'SHA512' }): boolean {
        if (typeof password !== 'string') {
            throw new TypeError('The password must be a string.');
        }

        if (typeof hashedPassword !== 'string') {
            throw new TypeError('The hashed password must be a string.');
        }

        if (!this.#_helpers.isPasswordVerificationOptions(options)) {
            throw new Error('The options must be a PasswordVerificationOptions object.');
        }

        const salt = options.salt;
        const algorithm = options.algorithm || 'SHA512';

        if (salt !== undefined && typeof salt !== 'string') {
            throw new TypeError('The salt must be a string if provided.');
        }

        if (!this.#_supportedAlgorithms.includes(algorithm)) {
            throw new Error(`The algorithm ${algorithm} is not supported.`);
        }

        // Combine the password and salt (if provided) and hash it
        const inputToHash = salt ? password + salt : password;
        const hashedInput = this.#_hashing.hash(inputToHash, algorithm);

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

export default Passwords;