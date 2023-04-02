import { assert } from 'assertthat';
import { deriveKey } from '../../../lib/crypto/scrypt';

suite('Scrypt', (): void => {
  // Test vector taken from here (vector 3): https://www.rfc-editor.org/rfc/rfc7914#page-13
  test('returns correct key.', async (): Promise<void> => {
    const expectedKey = Buffer.from(
      '7023bdcb3afd7348461c06cd81fd38ebfda8fbba904f8e3ea9b543f6545da1f2d5432955613f0fcf62d49705242a9af9e61e85dc0d651e40dfcf017b45575887',
      'hex'
    );
    const salt = Buffer.from('SodiumChloride', 'utf8');

    const key = deriveKey('pleaseletmein', salt, 64, 16_384, 8, 1);

    assert.that(key).is.equalTo(expectedKey);
  });
});
