import { DriftConfig, DriftResult } from './types';

const DEFAULT_DRIFT_CONFIG: DriftConfig = {
  windowSize: 50,
  lambda: 0.15,          // EWMA smoothing factor
  cusumSlack: 0.5,       // CUSUM allowable slack
  cusumThreshold: 4.0,   // CUSUM decision threshold
  alertThreshold: 0.6,   // drift score to trigger alert
};

export class DriftMonitor {
  private config: DriftConfig;
  private observations: number[] = [];  // 1 = violation, 0 = clean

  // EWMA state
  private ewmaValue: number = 0;
  private ewmaBaseline: number = 0;
  private ewmaInitialized = false;
  private baselineSamples = 0;
  private readonly baselineWindow = 20;

  // CUSUM state — Page's cumulative sum for detecting mean shifts
  private cusumUpper: number = 0;
  private cusumLower: number = 0;
  private cusumTarget: number = 0;
  private cusumInitialized = false;

  constructor(config?: Partial<DriftConfig>) {
    this.config = { ...DEFAULT_DRIFT_CONFIG, ...config };
  }

  record(violated: boolean): void {
    const x = violated ? 1 : 0;
    this.observations.push(x);
    this.updateEWMA(x);
    this.updateCUSUM(x);
  }

  /**
   * EWMA — Exponentially Weighted Moving Average
   *
   * S_t = λ·x_t + (1−λ)·S_{t-1}
   *
   * The first `baselineWindow` observations establish the baseline mean.
   * After that, any sustained deviation from baseline signals drift.
   */
  private updateEWMA(x: number): void {
    if (!this.ewmaInitialized) {
      this.baselineSamples++;
      // Online mean for baseline
      this.ewmaBaseline += (x - this.ewmaBaseline) / this.baselineSamples;
      this.ewmaValue = this.ewmaBaseline;
      if (this.baselineSamples >= this.baselineWindow) {
        this.ewmaInitialized = true;
      }
    } else {
      this.ewmaValue = this.config.lambda * x + (1 - this.config.lambda) * this.ewmaValue;
    }
  }

  /**
   * CUSUM — Cumulative Sum control chart (Page 1954)
   *
   * Detects small, persistent shifts in the mean of a process.
   *
   * S_H(t) = max(0, S_H(t-1) + x_t − μ₀ − k)   upper sum (detecting increase)
   * S_L(t) = max(0, S_L(t-1) − x_t + μ₀ − k)   lower sum (detecting decrease)
   *
   * Signal when S_H or S_L exceeds threshold h.
   *
   * μ₀ = target mean (estimated from baseline)
   * k  = slack parameter (allowable shift before accumulation)
   * h  = decision threshold
   */
  private updateCUSUM(x: number): void {
    if (!this.cusumInitialized && this.baselineSamples >= this.baselineWindow) {
      this.cusumTarget = this.ewmaBaseline;
      this.cusumInitialized = true;
    }
    if (!this.cusumInitialized) return;

    const k = this.config.cusumSlack;
    this.cusumUpper = Math.max(0, this.cusumUpper + x - this.cusumTarget - k);
    this.cusumLower = Math.max(0, this.cusumLower - x + this.cusumTarget - k);
  }

  getDrift(): DriftResult {
    const n = this.observations.length;
    if (n === 0) {
      return {
        score: 0,
        trending: 'stable',
        alert: false,
        ewma: { current: 0, baseline: 0, deviation: 0 },
        cusum: { upper: 0, lower: 0, signal: false },
        windowViolationRate: 0,
        baselineViolationRate: 0,
        sampleSize: 0,
      };
    }

    // Window violation rate
    const windowStart = Math.max(0, n - this.config.windowSize);
    const window = this.observations.slice(windowStart);
    const windowRate = window.reduce((s, v) => s + v, 0) / window.length;

    // EWMA deviation from baseline (normalized to 0-1)
    const ewmaDeviation = Math.abs(this.ewmaValue - this.ewmaBaseline);
    const normalizedEwma = Math.min(1, ewmaDeviation * 2); // scale: 0.5 deviation = full score

    // CUSUM signal
    const cusumSignal = this.cusumUpper > this.config.cusumThreshold
      || this.cusumLower > this.config.cusumThreshold;
    const cusumScore = cusumSignal ? 1 : Math.max(
      this.cusumUpper / this.config.cusumThreshold,
      this.cusumLower / this.config.cusumThreshold,
    );

    // Combined drift score: weighted average of EWMA deviation and CUSUM score
    const score = Math.min(1, normalizedEwma * 0.4 + cusumScore * 0.6);

    // Trend direction
    let trending: DriftResult['trending'] = 'stable';
    if (n >= this.baselineWindow) {
      if (this.ewmaValue > this.ewmaBaseline + 0.05) trending = 'drifting-up';
      else if (this.ewmaValue < this.ewmaBaseline - 0.05) trending = 'drifting-down';
    }

    return {
      score,
      trending,
      alert: score >= this.config.alertThreshold,
      ewma: {
        current: this.ewmaValue,
        baseline: this.ewmaBaseline,
        deviation: ewmaDeviation,
      },
      cusum: {
        upper: this.cusumUpper,
        lower: this.cusumLower,
        signal: cusumSignal,
      },
      windowViolationRate: windowRate,
      baselineViolationRate: this.ewmaBaseline,
      sampleSize: n,
    };
  }

  reset(): void {
    this.observations = [];
    this.ewmaValue = 0;
    this.ewmaBaseline = 0;
    this.ewmaInitialized = false;
    this.baselineSamples = 0;
    this.cusumUpper = 0;
    this.cusumLower = 0;
    this.cusumTarget = 0;
    this.cusumInitialized = false;
  }
}
