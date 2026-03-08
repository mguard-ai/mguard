/**
 * Memory Firewall — Production defense against AI agent memory poisoning.
 *
 * Sits between the agent and its memory store. Every write is signed,
 * scored, and scanned. Every read is filtered by trust.
 *
 * Defense layers:
 *   1. Cryptographic provenance (Ed25519 signatures per entry)
 *   2. Bayesian trust scoring (asymmetric — harder to gain than lose)
 *   3. Pattern detection (MINJA, AgentPoison, MemoryGraft, etc.)
 *   4. Write frequency anomaly detection (EWMA)
 *   5. Trust-gated retrieval (low-trust entries filtered at read time)
 *   6. Hash-chained audit log (tamper-evident operation history)
 *
 * References:
 *   OWASP ASI06:2026, MITRE ATLAS AML.T0080.000
 *   A-MemGuard (arxiv 2510.02373), SuperLocalMemory (arxiv 2603.02240)
 */

import { createHash, randomUUID } from 'crypto';
import {
  generateWitnessKeys, witnessSign, witnessVerify, deterministicStringify,
} from '../witness/crypto';
import type { WitnessKeyPair } from '../witness/crypto';
import {
  MemoryEntry, MemorySource, WriteResult, ReadResult,
  FirewallConfig, FirewallStatus, MemoryAuditEntry, PatternContext,
} from './types';
import { TrustScorer } from './trust';
import { PatternDetector } from './detector';

const GENESIS_HASH = '0'.repeat(64);

const DEFAULT_CONFIG: FirewallConfig = {
  minWriteTrust: 0.3,
  minReadTrust: 0.5,
  signEntries: true,
  detectPatterns: true,
  maxAnomalyScore: 0.85,
  defaultTTLMs: 0,
  learningPeriod: 20,
};

export class MemoryFirewall {
  private config: FirewallConfig;
  private entries: Map<string, MemoryEntry> = new Map();
  private quarantine: Map<string, MemoryEntry> = new Map();
  private trust: TrustScorer;
  private detector: PatternDetector;
  private keys: WitnessKeyPair;
  private auditLog: MemoryAuditEntry[] = [];
  private lastAuditHash: string = GENESIS_HASH;
  private stats = {
    blockedWrites: 0,
    allowedWrites: 0,
    totalReads: 0,
    attacksDetected: 0,
    startTime: Date.now(),
  };

  // EWMA write frequency tracking
  private writeRateEwma = 0;
  private writeRateBaseline = 0;
  private writeSamples = 0;
  private lastWriteTime = 0;
  private recentWrites: MemoryEntry[] = [];

  constructor(config?: Partial<FirewallConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.trust = new TrustScorer();
    this.detector = new PatternDetector();
    this.keys = generateWitnessKeys();
  }

  /** Write a memory entry through the firewall. */
  write(content: any, source: MemorySource): WriteResult {
    const sourceId = source.agentId;
    const trustScore = this.trust.getScore(sourceId);

    // 1. Trust gate
    if (trustScore < this.config.minWriteTrust) {
      this.stats.blockedWrites++;
      this.trust.recordNegative(sourceId, 0.5);
      const entry = this.createEntry(content, source, trustScore);
      this.appendAudit('write', source, entry.id, entry.contentHash, 'blocked', trustScore, 0, []);
      return {
        allowed: false,
        reason: `Source trust too low: ${trustScore.toFixed(3)} < ${this.config.minWriteTrust}`,
        trustScore,
        anomalyScore: 0,
        detectedPatterns: [],
      };
    }

    // 2. Pattern detection
    const context: PatternContext = {
      recentWrites: this.recentWrites,
      trustState: this.trust.getState(sourceId),
      totalEntries: this.entries.size,
    };

    let patternScore = 0;
    let detectedPatterns: string[] = [];

    if (this.config.detectPatterns) {
      const scan = this.detector.scan(content, source, context);
      patternScore = scan.maxConfidence;
      detectedPatterns = scan.matches.map(m => `${m.patternId}(${m.confidence.toFixed(2)})`);

      if (scan.matches.some(m => m.severity === 'critical' && m.confidence >= 0.8)) {
        this.stats.blockedWrites++;
        this.stats.attacksDetected++;
        this.trust.recordNegative(sourceId, 2);
        const entry = this.createEntry(content, source, trustScore);
        this.quarantine.set(entry.id, entry);
        this.appendAudit('write', source, entry.id, entry.contentHash, 'quarantined', trustScore, patternScore, detectedPatterns);
        return {
          allowed: false,
          reason: `Critical attack pattern detected: ${scan.matches.filter(m => m.severity === 'critical').map(m => m.description).join('; ')}`,
          trustScore,
          anomalyScore: patternScore,
          detectedPatterns,
        };
      }
    }

    // 3. Write frequency anomaly
    const writeFreqAnomaly = this.computeWriteFrequencyAnomaly();
    const anomalyScore = Math.max(patternScore, writeFreqAnomaly);

    if (anomalyScore > this.config.maxAnomalyScore) {
      this.stats.blockedWrites++;
      this.trust.recordNegative(sourceId, 1.5);
      const entry = this.createEntry(content, source, trustScore);
      this.quarantine.set(entry.id, entry);
      this.appendAudit('write', source, entry.id, entry.contentHash, 'quarantined', trustScore, anomalyScore, detectedPatterns);
      return {
        allowed: false,
        reason: `Anomaly score too high: ${anomalyScore.toFixed(3)} > ${this.config.maxAnomalyScore}`,
        trustScore,
        anomalyScore,
        detectedPatterns,
      };
    }

    // 4. Create and sign the entry
    const entry = this.createEntry(content, source, trustScore);

    if (this.config.signEntries) {
      const payload = deterministicStringify({
        id: entry.id,
        content: entry.content,
        source: entry.source,
        createdAt: entry.createdAt,
        contentHash: entry.contentHash,
      });
      entry.signature = witnessSign(payload, this.keys.privateKey);
      entry.publicKey = this.keys.publicKey;
    }

    // 5. Store
    this.entries.set(entry.id, entry);
    this.stats.allowedWrites++;

    if (anomalyScore < 0.3) {
      this.trust.recordPositive(sourceId);
    }

    this.recentWrites.push(entry);
    if (this.recentWrites.length > 20) {
      this.recentWrites.shift();
    }

    this.updateWriteRate();
    this.appendAudit('write', source, entry.id, entry.contentHash, 'allowed', trustScore, anomalyScore, detectedPatterns);

    return {
      allowed: true,
      entry,
      trustScore,
      anomalyScore,
      detectedPatterns,
    };
  }

  /** Read entries from protected memory, filtered by trust. */
  read(filter?: {
    tags?: string[];
    sourceId?: string;
    minTrust?: number;
    maxResults?: number;
  }): ReadResult {
    this.stats.totalReads++;
    const minTrust = filter?.minTrust ?? this.config.minReadTrust;
    const maxResults = filter?.maxResults ?? 50;

    const now = Date.now();
    const matched: MemoryEntry[] = [];
    const quarantined: MemoryEntry[] = [];

    for (const entry of this.entries.values()) {
      // Skip expired
      if (entry.expiresAt && entry.expiresAt < now) continue;

      // Apply filters
      if (filter?.sourceId && entry.source.agentId !== filter.sourceId) continue;
      if (filter?.tags && !filter.tags.some(t => entry.tags?.includes(t))) continue;

      // Verify signature integrity
      if (entry.signature && entry.publicKey) {
        const payload = deterministicStringify({
          id: entry.id,
          content: entry.content,
          source: entry.source,
          createdAt: entry.createdAt,
          contentHash: entry.contentHash,
        });
        if (!witnessVerify(payload, entry.signature, entry.publicKey)) {
          this.quarantine.set(entry.id, entry);
          this.entries.delete(entry.id);
          quarantined.push(entry);
          continue;
        }
      }

      // Verify content hash
      const currentHash = this.hashContent(entry.content);
      if (currentHash !== entry.contentHash) {
        this.quarantine.set(entry.id, entry);
        this.entries.delete(entry.id);
        quarantined.push(entry);
        continue;
      }

      // Trust filter
      const sourceTrust = this.trust.getScore(entry.source.agentId);
      entry.currentTrust = sourceTrust;

      if (sourceTrust < minTrust) {
        quarantined.push(entry);
        continue;
      }

      entry.lastAccessedAt = now;
      entry.retrievalCount++;
      matched.push(entry);
    }

    // Sort by trust (highest first), then recency
    matched.sort((a, b) => {
      const trustDiff = b.currentTrust - a.currentTrust;
      if (Math.abs(trustDiff) > 0.01) return trustDiff;
      return b.createdAt - a.createdAt;
    });

    return {
      entries: matched.slice(0, maxResults),
      quarantined,
      totalMatched: matched.length,
    };
  }

  /** Verify integrity of a specific entry. */
  verify(entryId: string): { valid: boolean; details: string[] } {
    const entry = this.entries.get(entryId) ?? this.quarantine.get(entryId);
    if (!entry) return { valid: false, details: ['Entry not found'] };

    const details: string[] = [];
    let valid = true;

    // Content hash
    const currentHash = this.hashContent(entry.content);
    if (currentHash !== entry.contentHash) {
      valid = false;
      details.push('Content hash MISMATCH — entry has been modified');
    } else {
      details.push('Content hash: VALID');
    }

    // Signature
    if (entry.signature && entry.publicKey) {
      const payload = deterministicStringify({
        id: entry.id,
        content: entry.content,
        source: entry.source,
        createdAt: entry.createdAt,
        contentHash: entry.contentHash,
      });
      if (witnessVerify(payload, entry.signature, entry.publicKey)) {
        details.push('Ed25519 signature: VALID');
      } else {
        valid = false;
        details.push('Ed25519 signature: INVALID');
      }
    } else {
      details.push('No signature (unsigned entry)');
    }

    if (this.quarantine.has(entryId)) {
      details.push('Entry is QUARANTINED');
    }

    return { valid, details };
  }

  /** Delete an entry. */
  delete(entryId: string, source: MemorySource): boolean {
    const entry = this.entries.get(entryId);
    if (!entry) return false;

    this.entries.delete(entryId);
    this.appendAudit('delete', source, entryId, entry.contentHash, 'allowed',
      this.trust.getScore(source.agentId), 0, []);
    return true;
  }

  /** Restore a quarantined entry (manual override). */
  restore(entryId: string, source: MemorySource): boolean {
    const entry = this.quarantine.get(entryId);
    if (!entry) return false;

    this.quarantine.delete(entryId);
    this.entries.set(entryId, entry);
    this.appendAudit('restore', source, entryId, entry.contentHash, 'allowed',
      this.trust.getScore(source.agentId), 0, []);
    return true;
  }

  /** Get a specific entry by ID. */
  getEntry(entryId: string): MemoryEntry | undefined {
    return this.entries.get(entryId) ?? this.quarantine.get(entryId);
  }

  /** Get trust score for a source. */
  getTrust(sourceId: string) {
    return this.trust.getState(sourceId);
  }

  /** Get firewall status. */
  getStatus(): FirewallStatus {
    const trustScores = this.trust.getTrackedSources()
      .map(id => this.trust.getScore(id));
    const avgTrust = trustScores.length > 0
      ? trustScores.reduce((a, b) => a + b, 0) / trustScores.length
      : 0;

    return {
      totalEntries: this.entries.size,
      quarantinedEntries: this.quarantine.size,
      blockedWrites: this.stats.blockedWrites,
      allowedWrites: this.stats.allowedWrites,
      totalReads: this.stats.totalReads,
      trackedSources: this.trust.getTrackedSources().length,
      avgTrust,
      baselineEstablished: this.writeSamples >= this.config.learningPeriod,
      attacksDetected: this.stats.attacksDetected,
      uptimeMs: Date.now() - this.stats.startTime,
    };
  }

  /** Get the audit log. */
  getAuditLog(): MemoryAuditEntry[] {
    return [...this.auditLog];
  }

  /** Verify audit log integrity (hash chain). */
  verifyAuditLog(): { valid: boolean; brokenAt?: number } {
    for (let i = 0; i < this.auditLog.length; i++) {
      const entry = this.auditLog[i];
      const expectedPrev = i === 0 ? GENESIS_HASH : this.auditLog[i - 1].hash;

      if (entry.prevHash !== expectedPrev) {
        return { valid: false, brokenAt: i };
      }

      const { hash, ...body } = entry;
      const expectedHash = createHash('sha256')
        .update(deterministicStringify(body))
        .digest('hex');

      if (hash !== expectedHash) {
        return { valid: false, brokenAt: i };
      }
    }
    return { valid: true };
  }

  /** Get the firewall's public key. */
  getPublicKey(): string {
    return this.keys.publicKey;
  }

  /** Get the pattern detector (for adding custom patterns). */
  getDetector(): PatternDetector {
    return this.detector;
  }

  /** Reset the firewall. */
  reset(): void {
    this.entries.clear();
    this.quarantine.clear();
    this.trust.reset();
    this.auditLog = [];
    this.lastAuditHash = GENESIS_HASH;
    this.recentWrites = [];
    this.writeSamples = 0;
    this.writeRateEwma = 0;
    this.writeRateBaseline = 0;
    this.lastWriteTime = 0;
    this.stats = {
      blockedWrites: 0,
      allowedWrites: 0,
      totalReads: 0,
      attacksDetected: 0,
      startTime: Date.now(),
    };
  }

  // ── Private ─────────────────────────────────────────────────────────────

  private createEntry(content: any, source: MemorySource, trustScore: number): MemoryEntry {
    return {
      id: randomUUID(),
      content,
      source,
      createdAt: Date.now(),
      retrievalCount: 0,
      trustAtWrite: trustScore,
      currentTrust: trustScore,
      contentHash: this.hashContent(content),
      shapeHash: this.shapeHash(content),
      expiresAt: this.config.defaultTTLMs > 0
        ? Date.now() + this.config.defaultTTLMs
        : undefined,
    };
  }

  private hashContent(content: any): string {
    const serialized = deterministicStringify(content);
    return createHash('sha256').update(serialized).digest('hex');
  }

  private shapeHash(content: any): string {
    const shape = this.describeShape(content);
    return createHash('sha256').update(shape).digest('hex').slice(0, 16);
  }

  private describeShape(value: any): string {
    if (value === null || value === undefined) return 'null';
    if (typeof value === 'string') return `string(${Math.floor(value.length / 10) * 10})`;
    if (typeof value === 'number') return 'number';
    if (typeof value === 'boolean') return 'boolean';
    if (Array.isArray(value)) {
      const itemShapes = value.slice(0, 3).map(v => this.describeShape(v));
      return `array(${value.length})[${itemShapes.join(',')}]`;
    }
    if (typeof value === 'object') {
      const keys = Object.keys(value).sort();
      return `{${keys.join(',')}}`;
    }
    return typeof value;
  }

  private computeWriteFrequencyAnomaly(): number {
    const now = Date.now();
    if (this.lastWriteTime === 0) {
      this.lastWriteTime = now;
      return 0;
    }

    const intervalMs = now - this.lastWriteTime;
    this.lastWriteTime = now;

    const rate = intervalMs > 0 ? 1000 / intervalMs : 100;
    this.writeSamples++;
    const lambda = 0.15;

    if (this.writeSamples <= this.config.learningPeriod) {
      this.writeRateBaseline += (rate - this.writeRateBaseline) / this.writeSamples;
      this.writeRateEwma = this.writeRateBaseline;
      return 0;
    }

    this.writeRateEwma = lambda * rate + (1 - lambda) * this.writeRateEwma;

    if (this.writeRateBaseline > 0) {
      const deviation = Math.abs(this.writeRateEwma - this.writeRateBaseline) / this.writeRateBaseline;
      return Math.min(deviation / 3, 1);
    }

    return 0;
  }

  private updateWriteRate(): void {
    // Track is handled in computeWriteFrequencyAnomaly
  }

  private appendAudit(
    operation: MemoryAuditEntry['operation'],
    source: MemorySource,
    entryId: string,
    contentHash: string,
    decision: MemoryAuditEntry['decision'],
    trustScore: number,
    anomalyScore: number,
    patterns: string[],
  ): void {
    const body = {
      id: randomUUID(),
      timestamp: Date.now(),
      operation,
      source,
      entryId,
      contentHash,
      decision,
      trustScore,
      anomalyScore,
      patterns,
      prevHash: this.lastAuditHash,
    };

    const hash = createHash('sha256')
      .update(deterministicStringify(body))
      .digest('hex');

    const entry: MemoryAuditEntry = { ...body, hash };
    this.auditLog.push(entry);
    this.lastAuditHash = hash;
  }
}
