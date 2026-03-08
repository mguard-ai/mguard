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

// ── Multi-Witness Consensus ─────────────────────────────────────────────────

/** Abstract interface for any witness node (local or remote). */
export interface WitnessNode {
  submitCertificate(cert: WitnessCertificate): Promise<VerificationReceipt>;
  registerKey(agentId: string, publicKey: string): Promise<void>;
  getWitnessInfo(): Promise<{ witnessId: string; publicKey: string; protocol: string }>;
}

/** Configuration for multi-witness consensus. */
export interface ConsensusConfig {
  quorum: number;     // minimum agreeing witnesses for consensus
  timeout?: number;   // ms to wait per witness (default 5000)
}

/** Result of submitting a certificate to a witness network. */
export interface ConsensusResult {
  certificateId: string;
  agentId: string;
  consensus: boolean;
  quorum: number;
  agreeing: number;
  dissenting: number;
  unreachable: number;
  receipts: VerificationReceipt[];
  witnessResults: {
    witnessId: string;
    valid: boolean;
    details: string[];
  }[];
  timestamp: number;
}
