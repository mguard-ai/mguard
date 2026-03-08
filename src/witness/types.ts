/**
 * Witness service types — third-party attestation layer.
 */

import { AttestationCertificate, Antibody } from '../types';

/** Certificate with Ed25519 public-key signature (verifiable by anyone). */
export interface WitnessCertificate extends Omit<AttestationCertificate, 'signature'> {
  publicKey: string;
  signature: string;
  witnessVerifications?: WitnessVerification[];
}

/** A witness node's counter-signature on a certificate. */
export interface WitnessVerification {
  witnessId: string;
  witnessPublicKey: string;
  signature: string;
  verifiedAt: number;
  checks: string[];
}

/** Receipt returned when a certificate is submitted to the witness service. */
export interface VerificationReceipt {
  certificateId: string;
  agentId: string;
  contractId: string;
  witnessId: string;
  witnessPublicKey: string;
  verification: WitnessVerification;
  submittedAt: number;
  result: {
    valid: boolean;
    signatureValid: boolean;
    complianceValid: boolean;
    details: string[];
  };
}

/** Entry in the public certificate registry. */
export interface RegistryEntry {
  certificate: WitnessCertificate;
  receipt: VerificationReceipt;
  registeredAt: number;
}

/** Network-wide statistics. */
export interface NetworkStats {
  totalCertificates: number;
  totalAgents: number;
  totalVerifications: number;
  totalAntibodiesShared: number;
  avgComplianceRate: number;
  uptime: number;
}

/** Witness server configuration. */
export interface WitnessServerConfig {
  port?: number;
  host?: string;
  persistPath?: string;
}
