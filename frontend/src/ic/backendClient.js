import { Actor, HttpAgent } from '@dfinity/agent';
import { canisterId as generatedBackendCanisterId, idlFactory } from 'declarations/backend';

function normalizeHost(host) {
  const trimmed = host.trim();
  if (!trimmed || trimmed === '/api') {
    if (typeof window !== 'undefined' && window.location.hostname.endsWith('.localhost')) {
      return window.location.origin;
    }
    return '/api';
  }
  return trimmed;
}

function isLocalTarget(host) {
  return (
    host.startsWith('/api') ||
    host.includes('127.0.0.1') ||
    host.includes('localhost') ||
    host.endsWith('.localhost')
  );
}

export async function getBackendActor({ canisterId, host, identity }) {
  const id = (canisterId || generatedBackendCanisterId || '').trim();
  if (!id) {
    throw new Error('缺少 backend canister id（未从 dfx generate 声明或环境变量读取到）。');
  }

  const resolvedHost = normalizeHost(host);
  const agent = new HttpAgent({
    host: resolvedHost,
    identity
  });

  if (isLocalTarget(resolvedHost)) {
    await agent.fetchRootKey();
  }

  return Actor.createActor(idlFactory, {
    agent,
    canisterId: id
  });
}

export const defaultBackendCanisterId = generatedBackendCanisterId || '';
