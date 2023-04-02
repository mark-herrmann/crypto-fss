import crypto from 'crypto';

const algorithm = 'sha256';

const sign = (data: Buffer, key: Buffer): Buffer => {
  const hmac = crypto.createHmac(algorithm, key);

  hmac.update(data);

  return hmac.digest();
};

const verify = (data: Buffer, key: Buffer, macGiven: Buffer): boolean => {
  const macActual = sign(data, key);

  return macActual.equals(macGiven);
};

export { sign, verify };
