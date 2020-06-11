const Buffer = require('safe-buffer').Buffer;
const BigInteger = require('bigi');
// const schnorr = require('./bip-schnorr');
const schnorr = require('./src/schnorr');

// signing
const privateKey = BigInteger.fromHex('B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF');
const message = Buffer.from('243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89', 'hex');
const createdSignature = schnorr.sign(privateKey, message);
console.log('The signature is: ' + createdSignature.toString('hex'));

// verifying
const publicKey = Buffer.from('02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659', 'hex');
const signatureToVerify = Buffer.from('2A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D1E51A22CCEC35599B8F266912281F8365FFC2D035A230434A1A64DC59F7013FD', 'hex');
try {
  schnorr.verify(publicKey, message, signatureToVerify);
  console.log('The signature is valid.');
} catch (e) {
  console.error('The signature verification failed: ' + e);
}
