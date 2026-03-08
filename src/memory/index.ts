export { MemoryFirewall } from './firewall';
export { TrustScorer } from './trust';
export { PatternDetector, BUILTIN_PATTERNS } from './detector';
export { shield, shieldMem0, shieldLangChain } from './shield';
export type { ShieldOptions } from './shield';
export type {
  MemoryEntry, MemorySource, WriteResult, ReadResult,
  FirewallConfig, FirewallStatus, MemoryAuditEntry,
  TrustState, AttackPattern, PatternContext,
} from './types';
