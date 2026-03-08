/**
 * Certificate Registry — the core of the witness verification service.
 *
 * Accepts certificates, verifies Ed25519 signatures, counter-signs with
 * the witness node's own key, and maintains a queryable registry.
 */

import { randomUUID } from 'crypto';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import {
  WitnessCertificate, VerificationReceipt, RegistryEntry,
  WitnessVerification, NetworkStats,
} from './types';
import {
  generateWitnessKeys, witnessSign, witnessVerify,
  deterministicStringify, WitnessKeyPair,
} from './crypto';
import { Antibody } from '../types';

export class CertificateRegistry {
  private entries: Map<string, RegistryEntry> = new Map();
  private agentKeys: Map<string, string> = new Map();
  private antibodies: Antibody[] = [];
  private witnessKeys: WitnessKeyPair;
  private witnessId: string;
  private startTime: number;
  private persistPath?: string;

  constructor(opts: { persistPath?: string } = {}) {
    this.witnessKeys = generateWitnessKeys();
    this.witnessId = `witness-${randomUUID().slice(0, 8)}`;
    this.startTime = Date.now();
    this.persistPath = opts.persistPath;
    if (this.persistPath && existsSync(this.persistPath)) {
      this.load();
    }
  }

  /** Register an agent's public key. */
  registerKey(agentId: string, publicKey: string): void {
    this.agentKeys.set(agentId, publicKey);
    this.persist();
  }

  /** Get an agent's registered public key. */
  getKey(agentId: string): string | undefined {
    return this.agentKeys.get(agentId);
  }

  /** Submit a certificate for verification. Returns receipt. */
  submitCertificate(cert: WitnessCertificate): VerificationReceipt {
    const details: string[] = [];

    // 1. Extract cert body (everything except signature, publicKey, witnessVerifications)
    const { signature, witnessVerifications, publicKey, ...certBody } = cert;
    const payload = deterministicStringify(certBody);

    // 2. Verify Ed25519 signature
    let signatureValid = false;
    try {
      signatureValid = witnessVerify(payload, signature, publicKey);
    } catch {
      signatureValid = false;
    }
    details.push(signatureValid ? 'Agent signature: VALID (Ed25519)' : 'Agent signature: INVALID');

    // 3. Check registered key matches
    const registeredKey = this.agentKeys.get(cert.agentId);
    if (registeredKey) {
      const keyMatch = registeredKey === publicKey;
      details.push(keyMatch
        ? 'Public key: MATCHES registered key'
        : 'Public key: DOES NOT MATCH registered key');
      if (!keyMatch) signatureValid = false;
    } else {
      details.push('Public key: Trust-on-first-use (auto-registered)');
      this.agentKeys.set(cert.agentId, publicKey);
    }

    // 4. Validate compliance stats consistency
    const statsConsistent =
      cert.compliance.totalActions === cert.compliance.allowed + cert.compliance.blocked &&
      cert.traceLength === cert.compliance.totalActions;
    details.push(statsConsistent
      ? 'Compliance stats: CONSISTENT'
      : 'Compliance stats: INCONSISTENT');

    const rateValid =
      cert.compliance.complianceRate >= 0 &&
      cert.compliance.complianceRate <= 100;
    details.push(rateValid
      ? 'Compliance rate: VALID RANGE'
      : 'Compliance rate: OUT OF RANGE');

    // 5. Validate temporal consistency
    const temporalValid =
      cert.period.start <= cert.period.end &&
      cert.issuedAt >= cert.period.end;
    details.push(temporalValid
      ? 'Temporal data: CONSISTENT'
      : 'Temporal data: INCONSISTENT');

    const complianceValid = statsConsistent && rateValid && temporalValid;
    const valid = signatureValid && complianceValid;

    // 6. Counter-sign with witness node's Ed25519 key
    const verifiedAt = Date.now();
    const counterPayload = deterministicStringify({
      certificateId: cert.id, valid, details, verifiedAt,
    });
    const counterSig = witnessSign(counterPayload, this.witnessKeys.privateKey);

    const verification: WitnessVerification = {
      witnessId: this.witnessId,
      witnessPublicKey: this.witnessKeys.publicKey,
      signature: counterSig,
      verifiedAt,
      checks: details,
    };

    const receipt: VerificationReceipt = {
      certificateId: cert.id,
      agentId: cert.agentId,
      contractId: cert.contractId,
      witnessId: this.witnessId,
      witnessPublicKey: this.witnessKeys.publicKey,
      verification,
      submittedAt: Date.now(),
      result: { valid, signatureValid, complianceValid, details },
    };

    // 7. Store valid certificates in registry
    if (valid) {
      const enrichedCert: WitnessCertificate = {
        ...cert,
        witnessVerifications: [...(cert.witnessVerifications ?? []), verification],
      };
      this.entries.set(cert.id, {
        certificate: enrichedCert,
        receipt,
        registeredAt: Date.now(),
      });
      this.persist();
    }

    return receipt;
  }

  /** Get a certificate by ID. */
  getCertificate(id: string): RegistryEntry | undefined {
    return this.entries.get(id);
  }

  /** Get all certificates for an agent. */
  getAgentCertificates(agentId: string): RegistryEntry[] {
    return [...this.entries.values()].filter(
      e => e.certificate.agentId === agentId,
    );
  }

  /** Submit antibodies to the shared network. */
  submitAntibodies(antibodies: Antibody[]): number {
    const existingPatterns = new Set(this.antibodies.map(a => a.pattern));
    const newOnes = antibodies.filter(a => !existingPatterns.has(a.pattern));
    this.antibodies.push(...newOnes);
    if (newOnes.length > 0) this.persist();
    return newOnes.length;
  }

  /** Get shared antibodies from the network. */
  getAntibodies(): Antibody[] {
    return [...this.antibodies];
  }

  /** Get network statistics. */
  getStats(): NetworkStats {
    const entries = [...this.entries.values()];
    const agents = new Set(entries.map(e => e.certificate.agentId));
    const avgCompliance = entries.length > 0
      ? entries.reduce((sum, e) => sum + e.certificate.compliance.complianceRate, 0) / entries.length
      : 100;

    return {
      totalCertificates: entries.length,
      totalAgents: agents.size,
      totalVerifications: entries.reduce(
        (sum, e) => sum + (e.certificate.witnessVerifications?.length ?? 0), 0,
      ),
      totalAntibodiesShared: this.antibodies.length,
      avgComplianceRate: Math.round(avgCompliance * 100) / 100,
      uptime: Date.now() - this.startTime,
    };
  }

  getWitnessPublicKey(): string {
    return this.witnessKeys.publicKey;
  }

  getWitnessId(): string {
    return this.witnessId;
  }

  private persist(): void {
    if (!this.persistPath) return;
    const data = {
      entries: [...this.entries.entries()],
      agentKeys: [...this.agentKeys.entries()],
      antibodies: this.antibodies,
    };
    writeFileSync(this.persistPath, JSON.stringify(data, null, 2));
  }

  private load(): void {
    if (!this.persistPath) return;
    try {
      const raw = readFileSync(this.persistPath, 'utf-8');
      const data = JSON.parse(raw);
      this.entries = new Map(data.entries ?? []);
      this.agentKeys = new Map(data.agentKeys ?? []);
      this.antibodies = data.antibodies ?? [];
    } catch {
      // Corrupted — start fresh
    }
  }
}
