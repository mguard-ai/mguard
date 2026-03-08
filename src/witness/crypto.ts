/**
 * Ed25519 cryptographic primitives for the Witness protocol.
 *
 * Asymmetric signatures — anyone with the public key can verify.
 * This is what makes third-party attestation possible.
 */

import {
  generateKeyPairSync, sign, verify,
  createPrivateKey, createPublicKey,
} from 'crypto';

export interface WitnessKeyPair {
  publicKey: string;   // base64 DER SPKI
  privateKey: string;  // base64 DER PKCS8
}

/** Generate an Ed25519 key pair for witness protocol signing. */
export function generateWitnessKeys(): WitnessKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKey: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
  };
}

/** Sign data with an Ed25519 private key. Returns base64 signature. */
export function witnessSign(data: string, privateKeyBase64: string): string {
  const key = createPrivateKey({
    key: Buffer.from(privateKeyBase64, 'base64'),
    format: 'der',
    type: 'pkcs8',
  });
  return sign(null, Buffer.from(data), key).toString('base64');
}

/** Verify an Ed25519 signature against a public key. */
export function witnessVerify(
  data: string,
  signatureBase64: string,
  publicKeyBase64: string,
): boolean {
  const key = createPublicKey({
    key: Buffer.from(publicKeyBase64, 'base64'),
    format: 'der',
    type: 'spki',
  });
  return verify(null, Buffer.from(data), key, Buffer.from(signatureBase64, 'base64'));
}

/** Deterministic JSON serialization — recursively sort all object keys. */
export function deterministicStringify(obj: any): string {
  if (obj === null || obj === undefined) return JSON.stringify(obj);
  if (typeof obj !== 'object') return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return '[' + obj.map(v => deterministicStringify(v)).join(',') + ']';
  }
  const keys = Object.keys(obj).sort();
  const entries = keys.map(k =>
    `${JSON.stringify(k)}:${deterministicStringify(obj[k])}`,
  );
  return '{' + entries.join(',') + '}';
}
