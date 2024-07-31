import authCrypto from '../src/manager';

describe('Testing the "crypto" module:', () => {
    const phrase = 'MyNameIsAhmad';

    test('Generating salt', () => {
        const salt = authCrypto.crypto.generateSalt();

        expect(typeof salt).toBe('string');
        expect(salt.length).toBe(512);
    })

    describe('Hashing', () => {
        test('Hashing with MD5', () => {
            const hashed = authCrypto.crypto.hash(phrase, 'MD5');
            expect(hashed).toBe('a9a92c22bfd2e918273f754fb310ee1f');
        })

        test('Hashing with SHA1', () => {
            const hashed = authCrypto.crypto.hash(phrase, 'SHA1');
            expect(hashed).toBe('9db98fc8ea0264c13929de7d3f6bf708b110ee15');
        })

        test('Hashing with SHA256', () => {
            const hashed = authCrypto.crypto.hash(phrase, 'SHA256');
            expect(hashed).toBe('1ec9c48e68884e304e04ed1c3275585dfc48516cd42ae432ca9cc99b312f22b3');
        })

        test('Hashing with SHA512', () => {
            const hashed = authCrypto.crypto.hash(phrase, 'SHA512');
            expect(hashed).toBe('89dfdecbcfbf480874369528acc809f9d9d73b0ab71dcf403edc3d1d9f601ed87dd772ee48ffab0bd5b6fc92ac2eb184da97c90c3cc8e18e34a43a1184b193c4');
        })
    })

    describe('Hashing with salting', () => {
        const salt = 'NasriyaSoftware';

        test('Hashing with MD5', () => {
            const hashed = authCrypto.crypto.saltHash(phrase, salt, 'MD5');
            expect(hashed).toBe('f12188936d12b3f77c80f67135f88859');
        })

        test('Hashing with SHA1', () => {
            const hashed = authCrypto.crypto.saltHash(phrase, salt, 'SHA1');
            expect(hashed).toBe('e48496ec8cf52716d2526f7400c5a7478680930e');
        })

        test('Hashing with SHA256', () => {
            const hashed = authCrypto.crypto.saltHash(phrase, salt, 'SHA256');
            expect(hashed).toBe('074c3646ba37e27422c4d2c59682ed7906df18c90f243d33c0bcab08c72b67f4');
        })

        test('Hashing with SHA512', () => {
            const hashed = authCrypto.crypto.saltHash(phrase, salt, 'SHA512');
            expect(hashed).toBe('e80daa35ce4144b943f9d09129ae28b33d702bde13bf62261bdfc0e60d1393a905fbcf17083c1c8c57491ff83d8b39eba43c9221067a28b8aee57fee60cb9931');
        })
    })
})