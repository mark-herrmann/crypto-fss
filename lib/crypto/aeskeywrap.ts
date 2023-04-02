import crypto from 'crypto';

const algorithm = 'id-aes256-wrap';
const iv = Buffer.from('A6'.repeat(8), 'hex');

const wrapKey = (keyData: Buffer, kekData: Buffer): string => {
  const cipher = crypto.createCipheriv(algorithm, kekData, iv);
  const wrappedKey = cipher.update(keyData);

  cipher.final();

  return wrappedKey.toString('base64');
};

const unwrapKey = (wrappedKeyData: string, kekData: Buffer): Buffer => {
  const cipher = crypto.createDecipheriv(algorithm, kekData, iv);
  const wrappedKey = Buffer.from(wrappedKeyData, 'base64');
  const key = cipher.update(wrappedKey);

  cipher.final();

  return key;
};

export { wrapKey, unwrapKey };
