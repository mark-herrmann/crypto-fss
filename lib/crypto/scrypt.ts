// eslint-disable-next-line eslint-comments/disable-enable-pair
/* eslint-disable id-length */
import crypto from 'crypto';

const deriveKey = (password: string, salt: Buffer, keyLen: number, N: number, r: number, p: number): Buffer =>
  // eslint-disable-next-line no-sync
  crypto.scryptSync(password, salt, keyLen, { N, r, p });

export { deriveKey };
