/*
* muSig non-interactive
*/
const Buffer = require('safe-buffer').Buffer;
const BigInteger = require('bigi');
const muSig = require('./src/mu-sig');
const schnorr = require('./src/schnorr');

// muSig non-interactive (not part of any BIP yet, see https://blockstream.com/2018/01/23/musig-key-aggregation-schnorr-signatures/)
const privateKey1 = BigInteger.fromHex('B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF');
const privateKey2 = BigInteger.fromHex('C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C7');
const message = Buffer.from('243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89', 'hex');
const aggregatedSignature = muSig.nonInteractive([privateKey1, privateKey2], message);

// verifying an aggregated signature
const publicKey1 = Buffer.from('02DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659', 'hex');
const publicKey2 = Buffer.from('03FAC2114C2FBB091527EB7C64ECB11F8021CB45E8E7809D3C0938E4B8C0E5F84B', 'hex');
const X = muSig.pubKeyCombine([publicKey1, publicKey2]);
try {
  schnorr.verify(X, message, aggregatedSignature);
  console.log('The signature is valid.');
} catch (e) {
  console.error('The signature verification failed: ' + e);
}
