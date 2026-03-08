/**
 * Memory Firewall Types
 *
 * Type definitions for the AI Agent Memory Firewall module.
 * Defense against MINJA, AgentPoison, MemoryGraft, and InjecMEM attacks.
 */

// ── Memory Entry ────────────────────────────────────────────────────────────

/** A memory entry with provenance metadata. */
export interface MemoryEntry {
  id: string;
  content: any;
  source: MemorySource;
  createdAt: number;
  lastAccessedAt?: number;
  retrievalCount: number;
  signature?: string;
  publicKey?: string;
  trustAtWrite: number;
  currentTrust: number;
  contentHash: string;
  shapeHash: string;
  tags?: string[];
  expiresAt?: number;
}

/** Source provenance for a memory entry. */
export interface MemorySource {
  agentId: string;
  protocol: 'direct' | 'tool-call' | 'conversation' | 'import' | 'system';
  sessionId: string;
  triggerQuery?: string;
}

// ── Operations ──────────────────────────────────────────────────────────────

/** Result of a memory write operation. */
export interface WriteResult {
  allowed: boolean;
  entry?: MemoryEntry;
  reason?: string;
  trustScore: number;
  anomalyScore: number;
  detectedPatterns: string[];
}

/** Result of a memory read/retrieval operation. */
export interface ReadResult {
  entries: MemoryEntry[];
  quarantined: MemoryEntry[];
  totalMatched: number;
}

// ── Configuration ───────────────────────────────────────────────────────────

/** Configuration for the memory firewall. */
export interface FirewallConfig {
  /** Minimum trust score to allow writes (default: 0.3). */
  minWriteTrust: number;
  /** Minimum trust score for retrieval inclusion (default: 0.5). */
  minReadTrust: number;
  /** Enable Ed25519 signing of entries (default: true). */
  signEntries: boolean;
  /** Enable pattern detection (default: true). */
  detectPatterns: boolean;
  /** Maximum anomaly score before blocking write (default: 0.85). */
  maxAnomalyScore: number;
  /** Default TTL for entries in ms (0 = no expiry). */
  defaultTTLMs: number;
  /** Learning period for baseline (number of writes). */
  learningPeriod: number;
}

// ── Trust ───────────────────────────────────────────────────────────────────

/** Trust state for a source (Beta-Binomial model). */
export interface TrustState {
  score: number;
  alpha: number;
  beta: number;
  totalInteractions: number;
  positiveSignals: number;
  negativeSignals: number;
  firstSeen: number;
  lastSeen: number;
}

// ── Audit ───────────────────────────────────────────────────────────────────

/** Audit log entry for memory operations. */
export interface MemoryAuditEntry {
  id: string;
  timestamp: number;
  operation: 'write' | 'read' | 'delete' | 'quarantine' | 'restore';
  source: MemorySource;
  entryId: string;
  contentHash: string;
  decision: 'allowed' | 'blocked' | 'quarantined';
  trustScore: number;
  anomalyScore: number;
  patterns: string[];
  hash: string;
  prevHash: string;
}

// ── Patterns ────────────────────────────────────────────────────────────────

/** Known attack pattern detector. */
export interface AttackPattern {
  id: string;
  description: string;
  detect: (content: any, source: MemorySource, context: PatternContext) => number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  mitreId?: string;
}

/** Context provided to pattern detectors. */
export interface PatternContext {
  recentWrites: MemoryEntry[];
  trustState: TrustState;
  totalEntries: number;
}

// ── Status ──────────────────────────────────────────────────────────────────

/** Overall firewall status. */
export interface FirewallStatus {
  totalEntries: number;
  quarantinedEntries: number;
  blockedWrites: number;
  allowedWrites: number;
  totalReads: number;
  trackedSources: number;
  avgTrust: number;
  baselineEstablished: boolean;
  attacksDetected: number;
  uptimeMs: number;
}
