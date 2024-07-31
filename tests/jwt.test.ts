import authCrypto from '../src/manager';

describe('Testing the JWT module', () => {
    const payload = { name: 'Nasriya Software' }
    let generatedToken: string;

    test('Generating', () => {
        generatedToken = authCrypto.jwt.generate(payload);
        expect(generatedToken).toBeTruthy()
    })

    test('Verifying', () => {        
        const result = authCrypto.jwt.verify(generatedToken);
        expect(result.valid).toBe(true);
    })
})