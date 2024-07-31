import authCrypto from '../src/manager';

describe('Testing the JWT module', () => {
    const payload = { name: 'Nasriya Software' }

    test('Generating', () => {
        const token = authCrypto.jwt.generate(payload);
        expect(token).toBe('eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiTmFzcml5YSBTb2Z0d2FyZSJ9.ylGm0z0gmQ0gsR3rgZMqTZTW6Bu0rWcCd0LreRx9WmP5UvLFyCm0-Kz0YlhuVbnSS12i8hLdfD6gdCHYJ4xdGw')
    })

    test('Verifying', () => {
        const token = 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiTmFzcml5YSBTb2Z0d2FyZSIsIndlYnNpdGUiOiJ3d3cubmFzcml5YS5uZXQifQ.K_zFYjx3tVFa4OnWik4HjFL_CqGdHvC7sj2Xa-nCQQWvEGF5GPS0KpKa0WL52y3tblhsZc6so9JL0kzluxPH7w';
        const result = authCrypto.jwt.verify(token);
        expect(result.valid).toBe(true);
    })
})