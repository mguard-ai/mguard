/**
 * Multi-Witness Consensus — Byzantine fault-tolerant certificate verification.
 *
 * A certificate is submitted to N independent witness nodes in parallel.
 * Consensus is reached when >= quorum witnesses agree it is valid.
 * Even if some witnesses are compromised or offline, the network holds.
 *
 * BFT guarantee: with quorum = ceil(2n/3), tolerates floor(n/3) faulty nodes.
 */

import { CertificateRegistry } from './registry';
import {
  WitnessNode, WitnessCertificate, VerificationReceipt,
  ConsensusConfig, ConsensusResult,
} from './types';

/** In-process witness node — wraps a CertificateRegistry for local consensus. */
export class LocalWitnessNode implements WitnessNode {
  readonly registry: CertificateRegistry;

  constructor(opts: { persistPath?: string } = {}) {
    this.registry = new CertificateRegistry(opts);
  }

  async submitCertificate(cert: WitnessCertificate): Promise<VerificationReceipt> {
    return this.registry.submitCertificate(cert);
  }

  async registerKey(agentId: string, publicKey: string): Promise<void> {
    this.registry.registerKey(agentId, publicKey);
  }

  async getWitnessInfo(): Promise<{ witnessId: string; publicKey: string; protocol: string }> {
    return {
      witnessId: this.registry.getWitnessId(),
      publicKey: this.registry.getWitnessPublicKey(),
      protocol: 'witness/1.0',
    };
  }
}

/** Orchestrates multi-witness consensus for certificate verification. */
export class WitnessNetwork {
  private nodes: WitnessNode[] = [];
  private quorum: number;
  private timeout: number;

  constructor(config: ConsensusConfig) {
    this.quorum = config.quorum;
    this.timeout = config.timeout ?? 5000;
  }

  addNode(node: WitnessNode): void {
    this.nodes.push(node);
  }

  removeNode(index: number): WitnessNode | undefined {
    return this.nodes.splice(index, 1)[0];
  }

  get nodeCount(): number {
    return this.nodes.length;
  }

  getNodes(): WitnessNode[] {
    return [...this.nodes];
  }

  /** Register an agent's public key on all witness nodes. */
  async registerKeyOnAll(agentId: string, publicKey: string): Promise<void> {
    await Promise.allSettled(
      this.nodes.map(n =>
        Promise.race([
          n.registerKey(agentId, publicKey),
          new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error('timeout')), this.timeout)
          ),
        ]),
      ),
    );
  }

  /** Submit a certificate to all witnesses and compute consensus. */
  async submitForConsensus(cert: WitnessCertificate): Promise<ConsensusResult> {
    const settled = await Promise.allSettled(
      this.nodes.map(async (node) => {
        const receipt = await Promise.race([
          node.submitCertificate(cert),
          new Promise<never>((_, reject) =>
            setTimeout(() => reject(new Error('timeout')), this.timeout)
          ),
        ]);
        const info = await node.getWitnessInfo();
        return { receipt, witnessId: info.witnessId };
      }),
    );

    const receipts: VerificationReceipt[] = [];
    const witnessResults: ConsensusResult['witnessResults'] = [];
    let agreeing = 0;
    let dissenting = 0;
    let unreachable = 0;

    for (const result of settled) {
      if (result.status === 'fulfilled') {
        receipts.push(result.value.receipt);
        const valid = result.value.receipt.result.valid;
        if (valid) agreeing++;
        else dissenting++;
        witnessResults.push({
          witnessId: result.value.witnessId,
          valid,
          details: result.value.receipt.result.details,
        });
      } else {
        unreachable++;
        witnessResults.push({
          witnessId: 'unreachable',
          valid: false,
          details: [result.reason instanceof Error ? result.reason.message : 'unreachable'],
        });
      }
    }

    return {
      certificateId: cert.id,
      agentId: cert.agentId,
      consensus: agreeing >= this.quorum,
      quorum: this.quorum,
      agreeing,
      dissenting,
      unreachable,
      receipts,
      witnessResults,
      timestamp: Date.now(),
    };
  }

  /** Compute the BFT-optimal quorum for N nodes: ceil(2N/3). */
  static bftQuorum(nodeCount: number): number {
    return Math.ceil((2 * nodeCount) / 3);
  }
}
