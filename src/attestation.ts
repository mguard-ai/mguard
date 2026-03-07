/**
 * Attestation — Cryptographic proof of agent behavioral compliance.
 *
 * Hash-chained execution traces + Merkle roots + signed certificates.
 * Verifiable by any third party without access to agent internals.
 *
 * Protocol: witness/1.0
 */

import { createHash, createHmac, randomUUID } from 'crypto';
import {
  TraceEntry, AttestationCertificate, VerificationResult,
} from './types';

// ── Hash Chain ──────────────────────────────────────────────────────────────

const GENESIS_HASH = '0'.repeat(64);

export class HashChain {
  private entries: TraceEntry[] = [];
  private contractId: string;

  constructor(contractId: string) {
    this.contractId = contractId;
  }

  append(
    input: any,
    output: any,
    decision: 'allowed' | 'blocked',
    violations: string[],
  ): TraceEntry {
    const index = this.entries.length;
    const prevHash = index === 0 ? GENESIS_HASH : this.entries[index - 1].hash;
    const timestamp = Date.now();

    const payload = this.serializeEntry({
      index, timestamp, input, output,
      contractId: this.contractId, decision, violations, prevHash,
    });

    const hash = createHash('sha256').update(payload).digest('hex');

    const entry: TraceEntry = {
      index, timestamp, input, output,
      contractId: this.contractId, decision, violations, hash, prevHash,
    };

    this.entries.push(entry);
    return entry;
  }

  /** Verify the entire chain is intact (no tampering). */
  verify(): { valid: boolean; brokenAt?: number } {
    for (let i = 0; i < this.entries.length; i++) {
      const entry = this.entries[i];
      const expectedPrev = i === 0 ? GENESIS_HASH : this.entries[i - 1].hash;

      if (entry.prevHash !== expectedPrev) {
        return { valid: false, brokenAt: i };
      }

      const payload = this.serializeEntry({
        index: entry.index, timestamp: entry.timestamp,
        input: entry.input, output: entry.output,
        contractId: entry.contractId, decision: entry.decision,
        violations: entry.violations, prevHash: entry.prevHash,
      });

      const expectedHash = createHash('sha256').update(payload).digest('hex');
      if (entry.hash !== expectedHash) {
        return { valid: false, brokenAt: i };
      }
    }
    return { valid: true };
  }

  /** Compute Merkle root of all trace entry hashes. */
  getMerkleRoot(): string {
    if (this.entries.length === 0) return GENESIS_HASH;

    let hashes = this.entries.map(e => e.hash);
    while (hashes.length > 1) {
      const next: string[] = [];
      for (let i = 0; i < hashes.length; i += 2) {
        const left = hashes[i];
        const right = hashes[i + 1] ?? left;
        next.push(createHash('sha256').update(left + right).digest('hex'));
      }
      hashes = next;
    }
    return hashes[0];
  }

  getEntries(): TraceEntry[] {
    return [...this.entries];
  }

  get length(): number {
    return this.entries.length;
  }

  reset(): void {
    this.entries = [];
  }

  private serializeEntry(data: Record<string, any>): string {
    return JSON.stringify(data);
  }
}

/** Recursively sort all object keys for deterministic serialization. */
function deterministicStringify(obj: any): string {
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

// ── Attestation Engine ──────────────────────────────────────────────────────

export class AttestationEngine {
  private secret: string;
  private agentId: string;

  constructor(agentId: string, secret?: string) {
    this.agentId = agentId;
    this.secret = secret ?? randomUUID();
  }

  /** Generate a signed attestation certificate from the current trace chain. */
  generateCertificate(
    chain: HashChain,
    contractId: string,
    driftScore: number,
    budgetUtilization: number,
  ): AttestationCertificate {
    const entries = chain.getEntries();
    const allowed = entries.filter(e => e.decision === 'allowed').length;
    const blocked = entries.filter(e => e.decision === 'blocked').length;
    const total = entries.length;

    const certBody = {
      id: randomUUID(),
      version: '1.0' as const,
      protocol: 'witness/1.0' as const,
      agentId: this.agentId,
      contractId,
      period: {
        start: total > 0 ? entries[0].timestamp : Date.now(),
        end: total > 0 ? entries[total - 1].timestamp : Date.now(),
      },
      traceRoot: chain.getMerkleRoot(),
      traceLength: total,
      compliance: {
        totalActions: total,
        allowed,
        blocked,
        complianceRate: total > 0 ? (allowed / total) * 100 : 100,
      },
      behavioral: {
        driftScore,
        budgetUtilization,
      },
      issuedAt: Date.now(),
    };

    const signature = this.sign(certBody);
    return { ...certBody, signature };
  }

  /** Verify an attestation certificate's signature and (optionally) chain integrity. */
  verifyCertificate(
    cert: AttestationCertificate,
    chain?: HashChain,
  ): VerificationResult {
    const details: string[] = [];

    // 1. Verify signature
    const { signature, ...certBody } = cert;
    const expectedSig = this.sign(certBody);
    const signatureValid = signature === expectedSig;
    details.push(signatureValid ? 'Signature: VALID' : 'Signature: INVALID');

    // 2. Verify chain integrity (if provided)
    let chainIntegrity = true;
    if (chain) {
      const chainResult = chain.verify();
      chainIntegrity = chainResult.valid;
      details.push(
        chainIntegrity
          ? 'Chain integrity: VALID'
          : `Chain integrity: BROKEN at entry ${chainResult.brokenAt}`,
      );

      // 3. Verify Merkle root matches
      const merkleMatch = chain.getMerkleRoot() === cert.traceRoot;
      details.push(merkleMatch ? 'Merkle root: MATCHES' : 'Merkle root: MISMATCH');
      if (!merkleMatch) chainIntegrity = false;

      // 4. Verify compliance stats match chain
      const entries = chain.getEntries();
      const actualAllowed = entries.filter(e => e.decision === 'allowed').length;
      const statsMatch =
        cert.compliance.allowed === actualAllowed &&
        cert.compliance.totalActions === entries.length;
      details.push(statsMatch ? 'Compliance stats: VERIFIED' : 'Compliance stats: MISMATCH');
      if (!statsMatch) chainIntegrity = false;
    }

    const complianceVerified =
      cert.compliance.complianceRate >= 0 &&
      cert.compliance.complianceRate <= 100;
    details.push(
      complianceVerified ? 'Compliance rate: VALID RANGE' : 'Compliance rate: OUT OF RANGE',
    );

    return {
      valid: signatureValid && chainIntegrity && complianceVerified,
      chainIntegrity,
      signatureValid,
      complianceVerified,
      details,
    };
  }

  getAgentId(): string {
    return this.agentId;
  }

  getSecret(): string {
    return this.secret;
  }

  private sign(data: any): string {
    const payload = deterministicStringify(data);
    return createHmac('sha256', this.secret).update(payload).digest('hex');
  }
}
