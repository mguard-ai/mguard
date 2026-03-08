/**
 * Witness Client — communicates with a witness verification service.
 */

import { WitnessCertificate, VerificationReceipt, RegistryEntry, NetworkStats } from './types';
import { Antibody } from '../types';

export class WitnessClient {
  private baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
  }

  /** Register an agent's public key with the witness service. */
  async registerKey(agentId: string, publicKey: string): Promise<void> {
    await this.post('/v1/keys', { agentId, publicKey });
  }

  /** Submit a certificate for verification. Returns the verification receipt. */
  async submitCertificate(cert: WitnessCertificate): Promise<VerificationReceipt> {
    return this.post('/v1/certificates', cert);
  }

  /** Get a certificate and its verification receipt by ID. */
  async getCertificate(id: string): Promise<RegistryEntry> {
    return this.get(`/v1/certificates/${encodeURIComponent(id)}`);
  }

  /** Get all certificates for an agent. */
  async getAgentCertificates(agentId: string): Promise<{ agentId: string; certificates: RegistryEntry[] }> {
    return this.get(`/v1/agents/${encodeURIComponent(agentId)}/certificates`);
  }

  /** Share antibodies with the network. */
  async shareAntibodies(antibodies: Antibody[]): Promise<{ added: number; total: number }> {
    return this.post('/v1/antibodies', { antibodies });
  }

  /** Fetch antibodies from the network. */
  async fetchAntibodies(): Promise<Antibody[]> {
    const result = await this.get('/v1/antibodies');
    return result.antibodies;
  }

  /** Get network statistics. */
  async getStats(): Promise<NetworkStats> {
    return this.get('/v1/stats');
  }

  /** Get witness node info. */
  async getWitnessInfo(): Promise<{ witnessId: string; publicKey: string; protocol: string }> {
    return this.get('/v1/witness');
  }

  private async get(path: string): Promise<any> {
    const res = await fetch(`${this.baseUrl}${path}`);
    if (!res.ok) {
      const errBody: any = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(errBody.error ?? `HTTP ${res.status}`);
    }
    return res.json();
  }

  private async post(path: string, body: any): Promise<any> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const errBody: any = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(errBody.error ?? `HTTP ${res.status}`);
    }
    return res.json();
  }
}
