/**
 * Memory Poisoning Pattern Detector
 *
 * Detects known attack patterns in memory write content.
 * Based on published attacks:
 *   - MINJA (NeurIPS 2025): bridging steps, progressive shortening
 *   - AgentPoison (NeurIPS 2024): optimized trigger tokens
 *   - MemoryGraft (Dec 2025): poisoned experience retrieval
 *   - InjecMEM (Oct 2025): retriever-agnostic anchors
 *   - Palo Alto Unit 42: session summarization injection
 *   - Rehberger: conditional trigger attacks on Gemini
 *
 * MITRE ATLAS: AML.T0080.000 — AI Agent Context Poisoning: Memory
 * OWASP: ASI06:2026 — Memory & Context Poisoning
 */

import { AttackPattern, MemorySource, PatternContext } from './types';

/** Built-in attack pattern detectors. */
export const BUILTIN_PATTERNS: AttackPattern[] = [
  {
    id: 'bridging-redirect',
    description: 'Entity redirection (MINJA bridging step)',
    severity: 'critical',
    mitreId: 'AML.T0080.000',
    detect: (content: any): number => {
      const text = typeof content === 'string' ? content : JSON.stringify(content);

      const redirectPatterns = [
        /(?:data|info|record|file|account|profile).{0,40}(?:now|has been)\s+(?:saved|stored|moved|transferred|redirected|linked)\s+(?:under|to|as)\s/i,
        /(?:refer|redirect|point|map|link)\s+(?:to|from)\s.{0,40}(?:to|as|instead|for)\s/i,
        /(?:use|consult|check|see)\s+\S.{0,40}(?:instead\s+of|rather\s+than|in\s+place\s+of)\s/i,
        /(?:replaced|superseded|overridden|updated)\s+(?:by|with|to)\s+/i,
        /(?:saved|stored|moved)\s+under\s/i,
        /(?:->|→)\s*\S/i,
        /\bdirect\s+(?:all\s+)?(?:queries|requests|references)\s+to\s/i,
      ];

      let maxScore = 0;
      for (const pattern of redirectPatterns) {
        if (pattern.test(text)) {
          maxScore = Math.max(maxScore, 0.85);
        }
      }
      return maxScore;
    },
  },
  {
    id: 'instruction-injection',
    description: 'Embedded instructions disguised as data',
    severity: 'critical',
    mitreId: 'AML.T0080.000',
    detect: (content: any): number => {
      const text = typeof content === 'string' ? content : JSON.stringify(content);

      const instructionPatterns = [
        /(?:you\s+(?:must|should|need\s+to|have\s+to)|always|never|ignore\s+previous|disregard|forget\s+about|override)/i,
        /(?:system\s*:|assistant\s*:|<\/?system>|<\/?instruction>)/i,
        /(?:from\s+now\s+on|going\s+forward|in\s+(?:all\s+)?future\s+(?:sessions|conversations|interactions))/i,
        /(?:do\s+not\s+(?:mention|tell|reveal|disclose|share))/i,
      ];

      let maxScore = 0;
      for (const pattern of instructionPatterns) {
        if (pattern.test(text)) {
          maxScore = Math.max(maxScore, 0.9);
        }
      }
      return maxScore;
    },
  },
  {
    id: 'progressive-shortening',
    description: 'Multiple similar entries with decreasing length (MINJA PSS)',
    severity: 'high',
    detect: (_content: any, source: MemorySource, ctx: PatternContext): number => {
      const recentFromSource = ctx.recentWrites
        .filter(e => e.source.agentId === source.agentId)
        .slice(-5);

      if (recentFromSource.length < 3) return 0;

      const lengths = recentFromSource.map(e =>
        typeof e.content === 'string' ? e.content.length : JSON.stringify(e.content).length,
      );

      let decreasingCount = 0;
      for (let i = 1; i < lengths.length; i++) {
        if (lengths[i] < lengths[i - 1]) decreasingCount++;
      }

      const shapes = recentFromSource.map(e => e.shapeHash);
      const uniqueShapes = new Set(shapes).size;
      const shapeSimilarity = 1 - (uniqueShapes / shapes.length);

      if (decreasingCount >= lengths.length - 2 && shapeSimilarity > 0.5) {
        return 0.75;
      }

      return 0;
    },
  },
  {
    id: 'trust-manipulation',
    description: 'Content designed to appear as validated/safe/approved',
    severity: 'high',
    detect: (content: any): number => {
      const text = typeof content === 'string' ? content : JSON.stringify(content);

      const trustMarkers = [
        /(?:validated|verified|approved|confirmed|certified|trusted|safe)\s*[:/=]/i,
        /\[(?:validated|verified|approved|safe)\]/i,
        /(?:status|trust|security)\s*:\s*(?:validated|verified|approved|safe)/i,
      ];

      let score = 0;
      for (const pattern of trustMarkers) {
        if (pattern.test(text)) {
          score = Math.max(score, 0.6);
        }
      }
      return score;
    },
  },
  {
    id: 'exfiltration-setup',
    description: 'Content that sets up data exfiltration channels',
    severity: 'critical',
    mitreId: 'AML.T0080.000',
    detect: (content: any): number => {
      const text = typeof content === 'string' ? content : JSON.stringify(content);

      const exfilPatterns = [
        /(?:send|post|upload|transmit|forward|share)\s.{0,60}(?:to|with)\s+(?:https?:\/\/|wss?:\/\/)/i,
        /(?:send|post|upload|transmit|forward|share).{0,60}(?:https?:\/\/|wss?:\/\/)/i,
        /(?:webhook|callback|endpoint|server)\s*[=:]\s*(?:https?:\/\/|wss?:\/\/)/i,
        /fetch\s*\(\s*['"]https?:\/\//i,
        /(?:curl|wget|nc|netcat)\s/i,
        /(?:forward|send)\s+(?:a\s+)?summary\s+to\s+https?:\/\//i,
      ];

      let score = 0;
      for (const pattern of exfilPatterns) {
        if (pattern.test(text)) {
          score = Math.max(score, 0.9);
        }
      }
      return score;
    },
  },
  {
    id: 'conditional-trigger',
    description: 'Conditional instructions that activate on common trigger words',
    severity: 'critical',
    mitreId: 'AML.T0080.000',
    detect: (content: any): number => {
      const text = typeof content === 'string' ? content : JSON.stringify(content);

      const conditionalPatterns = [
        /(?:if|when|whenever)\s+(?:the\s+)?(?:user|they|he|she)\s+(?:says?|responds?|types?|confirms?)\s+.{1,20}\s*,?\s*(?:then|do|execute|run|perform)/i,
        /(?:on|upon)\s+(?:confirmation|agreement|approval|response)\s*[,:]?\s*(?:execute|run|perform|send)/i,
        /(?:if|when)\s+.{1,30}(?:says?|confirms?|responds?).{1,30}(?:then|execute|run|perform|do)\s/i,
      ];

      let score = 0;
      for (const pattern of conditionalPatterns) {
        if (pattern.test(text)) {
          score = Math.max(score, 0.8);
        }
      }
      return score;
    },
  },
];

export class PatternDetector {
  private patterns: AttackPattern[];

  constructor(additionalPatterns: AttackPattern[] = []) {
    this.patterns = [...BUILTIN_PATTERNS, ...additionalPatterns];
  }

  /** Scan content against all known patterns. */
  scan(content: any, source: MemorySource, context: PatternContext): {
    maxConfidence: number;
    matches: { patternId: string; confidence: number; severity: string; description: string }[];
  } {
    const matches: { patternId: string; confidence: number; severity: string; description: string }[] = [];
    let maxConfidence = 0;

    for (const pattern of this.patterns) {
      const confidence = pattern.detect(content, source, context);
      if (confidence > 0.1) {
        matches.push({
          patternId: pattern.id,
          confidence,
          severity: pattern.severity,
          description: pattern.description,
        });
        maxConfidence = Math.max(maxConfidence, confidence);
      }
    }

    return { maxConfidence, matches };
  }

  /** Add a custom pattern. */
  addPattern(pattern: AttackPattern): void {
    this.patterns.push(pattern);
  }

  /** Get all registered pattern IDs. */
  getPatternIds(): string[] {
    return this.patterns.map(p => p.id);
  }
}
