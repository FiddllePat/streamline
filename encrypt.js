const kyber = require('crystals-kyber');
const crypto = require('crypto');

async function KeyGen768() {
  let pk_sk = await kyber.KeyGen768();
  let publicKey = Buffer.from(pk_sk[0]).toString('base64');
  let privateKey = Buffer.from(pk_sk[1]).toString('base64');
  return { public_key: publicKey, private_key: privateKey };
}

async function Encrypt768(publicKeyBase64, message) {
  try {
    let publicKey = Buffer.from(publicKeyBase64, 'base64');

    let c_ss = await kyber.Encrypt768(publicKey);
    let ciphertext = Buffer.from(c_ss[0]).toString('base64');
    let ss1 = Buffer.from(c_ss[1]).toString('base64');

    let ss_hash = crypto.createHash('sha256').update(Buffer.from(ss1, 'base64')).digest();

    let iv = crypto.randomBytes(16);
    let cipher = crypto.createCipheriv('aes-256-gcm', ss_hash, iv);
    let encryptedMessage = cipher.update(message, 'utf8', 'hex');
    encryptedMessage += cipher.final('hex');
    let authTag = cipher.getAuthTag();

    return `--streamline_begin--${iv.toString('hex')}--streamline--${authTag.toString('hex')}--streamline--${encryptedMessage}--streamline--${ciphertext}--streamline_end--`;
  } catch (err) {
    throw new Error(err);
  }
}

async function Decrypt768(privateKeyBase64, streamlineedMessage) {
  try {
    let privateKey = Buffer.from(privateKeyBase64, 'base64');

    let parts = streamlineedMessage.split('--streamline--');
    let parsedIV = Buffer.from(parts[0].split('--streamline_begin--')[1], 'hex');
    let parsedAuthTag = Buffer.from(parts[1], 'hex');
    let parsedEncryptedMessage = parts[2];
    let ciphertext = Buffer.from(parts[3].split('--streamline_end--')[0], 'base64');

    let ss2 = await kyber.Decrypt768(ciphertext, privateKey);
    let ss_hash = crypto.createHash('sha256').update(ss2).digest();

    let decipher = crypto.createDecipheriv('aes-256-gcm', ss_hash, parsedIV);
    decipher.setAuthTag(parsedAuthTag);

    let decryptedMessage = decipher.update(parsedEncryptedMessage, 'hex', 'utf8');
    decryptedMessage += decipher.final('utf8');

    return decryptedMessage;
  } catch (err) {
    throw new Error(err);
  }
}

module.exports = {
  KeyGen768,
  Encrypt768,
  Decrypt768
};