/**
 * Bayesian Trust Scoring for Memory Sources
 *
 * Beta-Binomial model with asymmetric updates.
 * Trust is harder to gain than lose — a single malicious write
 * costs more trust than a clean write earns.
 *
 * Based on SuperLocalMemory (arxiv 2603.02240) Bayesian trust defense.
 */

import { TrustState } from './types';

const DEFAULT_ALPHA = 2;      // Prior: slight benefit of doubt
const DEFAULT_BETA = 2;       // Prior: symmetric start
const POSITIVE_WEIGHT = 0.015; // Clean write reward
const NEGATIVE_WEIGHT = 0.05;  // Suspicious write penalty (~3x positive)
const DECAY_RATE = 0.001;      // Trust decay per hour of inactivity
const MAX_TRUST = 0.95;        // Never fully trust

export class TrustScorer {
  private sources: Map<string, TrustState> = new Map();

  /** Get or create trust state for a source. */
  getState(sourceId: string): TrustState {
    let state = this.sources.get(sourceId);
    if (!state) {
      state = {
        score: this.computeScore(DEFAULT_ALPHA, DEFAULT_BETA),
        alpha: DEFAULT_ALPHA,
        beta: DEFAULT_BETA,
        totalInteractions: 0,
        positiveSignals: 0,
        negativeSignals: 0,
        firstSeen: Date.now(),
        lastSeen: Date.now(),
      };
      this.sources.set(sourceId, state);
    }
    return state;
  }

  /** Record a positive signal (clean write). */
  recordPositive(sourceId: string): TrustState {
    const state = this.getState(sourceId);
    state.alpha += POSITIVE_WEIGHT;
    state.positiveSignals++;
    state.totalInteractions++;
    state.lastSeen = Date.now();
    state.score = this.computeScore(state.alpha, state.beta);
    return state;
  }

  /** Record a negative signal (suspicious or blocked write). */
  recordNegative(sourceId: string, severity: number = 1): TrustState {
    const state = this.getState(sourceId);
    state.beta += NEGATIVE_WEIGHT * severity;
    state.negativeSignals++;
    state.totalInteractions++;
    state.lastSeen = Date.now();
    state.score = this.computeScore(state.alpha, state.beta);
    return state;
  }

  /** Apply temporal decay — trust erodes during inactivity. */
  applyDecay(sourceId: string): TrustState {
    const state = this.getState(sourceId);
    const hoursSinceLastSeen = (Date.now() - state.lastSeen) / (1000 * 60 * 60);
    if (hoursSinceLastSeen > 1) {
      const decay = DECAY_RATE * hoursSinceLastSeen;
      state.beta += decay;
      state.score = this.computeScore(state.alpha, state.beta);
    }
    return state;
  }

  /** Get current trust score (with decay applied). */
  getScore(sourceId: string): number {
    if (!this.sources.has(sourceId)) {
      return this.computeScore(DEFAULT_ALPHA, DEFAULT_BETA);
    }
    return this.applyDecay(sourceId).score;
  }

  /** Get confidence in the trust estimate (0-1). */
  getConfidence(sourceId: string): number {
    const state = this.getState(sourceId);
    const n = state.totalInteractions;
    return Math.min(
      (state.alpha + state.positiveSignals) / (state.alpha + state.beta + n),
      MAX_TRUST,
    );
  }

  /** Get all tracked source IDs. */
  getTrackedSources(): string[] {
    return Array.from(this.sources.keys());
  }

  /** Remove a source's trust state. */
  removeSource(sourceId: string): boolean {
    return this.sources.delete(sourceId);
  }

  /** Reset all trust states. */
  reset(): void {
    this.sources.clear();
  }

  /** Beta-Binomial posterior mean, clamped to [0, MAX_TRUST]. */
  private computeScore(alpha: number, beta: number): number {
    const raw = alpha / (alpha + beta);
    return Math.max(0, Math.min(MAX_TRUST, raw));
  }
}
