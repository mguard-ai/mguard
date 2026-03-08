/**
 * Bridge between HarnessedAgent and the Witness protocol.
 *
 * Converts an HMAC-signed AttestationCertificate into an Ed25519-signed
 * WitnessCertificate that anyone can verify with the public key.
 */

import { HarnessedAgent } from '../types';
import { WitnessCertificate } from './types';
import { WitnessKeyPair, witnessSign, deterministicStringify } from './crypto';

/** Generate a WitnessCertificate from a HarnessedAgent using Ed25519 signing. */
export function createWitnessCertificate(
  agent: HarnessedAgent,
  keys: WitnessKeyPair,
  agentId?: string,
): WitnessCertificate {
  const hmacCert = agent.attest();
  const { signature: _hmacSig, ...certBody } = hmacCert;
  if (agentId) certBody.agentId = agentId;
  const payload = deterministicStringify(certBody);
  const signature = witnessSign(payload, keys.privateKey);

  return {
    ...certBody,
    publicKey: keys.publicKey,
    signature,
  };
}
