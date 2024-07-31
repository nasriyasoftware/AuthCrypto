export type HashAlgorithm = 'SHA256' | 'SHA512' | 'MD5' | 'SHA1';

/**Represents a valid JWT verification result. */
export interface ValidJWTVerification {
    valid: true;
    /**The decoded payload from the JWT */
    payload: JwtPayloadDecoded
}

/**Represents an invalid JWT verification result. */
export interface InvalidJWTVerification {
    valid: false;
    /**Explanation of why the JWT is invalid. */
    message: string;
}

export interface RandomOptions {
    /** Include numbers. Default: `true` */
    includeNumbers?: boolean;
    /** Include letters. Default: `true` */
    includeLetters?: boolean;
    /** Include symbols: ``!";#$%&'()*+,-./:;<=>?@[]^_`{|}~``. Default: `true` */
    includeSymbols?: boolean;
    /** Include lowercase characters. Default: `true` */
    includeLowerCaseChars?: boolean;
    /** Include uppercase characters. Default: `true` */
    includeUpperCaseChars?: boolean;
    /** Don't begin with a number or symbol. Default: `true` */
    beginWithLetter?: boolean;
    /** Don't use characters like i, l, 1, L, o, 0, O, etc. Default: `true` */
    noSimilarChars?: boolean;
    /** Don't use the same character more than once. Default: `false` */
    noDuplicateChars?: boolean;
    /** Don't use sequential characters, e.g. `abc`, `789`. Default: `true` */
    noSequentialChars?: boolean;
}

/**
 * Interface representing the structure of a JWT payload.
 * 
 * The properties in this interface are commonly included in JWT payloads.
 * They are marked as optional since not all JWTs will necessarily include all these properties.
 */
export interface JwtPayload {
    /**
     * A unique identifier for the user or entity.
     * @example '123456'
     */
    userId?: string;

    /**
     * The username or email of the user.
     * @example 'john.doe@example.com'
     */
    username?: string;

    /**
     * The role of the user, such as 'admin' or 'user'.
     * @example 'admin'
     */
    role?: string;

    /**
     * The token's expiration time, represented as a Unix timestamp (seconds since epoch).
     * @example 1622548800
     */
    exp?: number;

    /**
     * The issued at time, represented as a Unix timestamp (seconds since epoch).
     * @example 1622452400
     */
    iat?: number;

    /**
     * The intended audience of the token.
     * @example 'example.com'
     */
    aud?: string;

    /**
     * The issuer of the token.
     * @example 'auth.example.com'
     */
    iss?: string;

    /**
     * The subject of the token.
     * @example '123456'
     */
    sub?: string;

    /**
     * Additional custom claims.
     */
    [key: string]: any;
}

export type JwtPayloadCreation = Omit<JwtPayload, 'iat'>;

export interface JwtPayloadDecoded extends JwtPayload {
    /** Issuer of the token */
    iss: string;
    /** JWT issued at time in seconds since epoch */
    iat: number;
}