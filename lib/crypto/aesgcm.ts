import crypto from 'crypto';

const algorithm = 'aes-256-gcm';

const encrypt = async (data: Buffer, keyData: Buffer, iv: Buffer, additionalData: Buffer): Promise<Buffer> => {
  const cipher = crypto.createCipheriv(algorithm, keyData, iv);

  cipher.setAAD(additionalData);
  const ciphertext = cipher.update(data);

  cipher.final();
  const authTag = cipher.getAuthTag();

  return Buffer.concat([ ciphertext, authTag ]);
};

const decrypt = async (cipherAndTag: Buffer, keyData: Buffer, iv: Buffer, additionalData: Buffer): Promise<Buffer> => {
  const decipher = crypto.createDecipheriv(algorithm, keyData, iv);
  const ciphertext = cipherAndTag.subarray(0, -16);
  const authTag = cipherAndTag.subarray(-16);

  decipher.setAAD(additionalData);
  decipher.setAuthTag(authTag);
  const data = decipher.update(ciphertext);

  decipher.final();

  return data;
};

export { decrypt, encrypt };
