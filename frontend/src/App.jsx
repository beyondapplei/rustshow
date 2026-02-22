import { useEffect, useState } from 'react';
import { AuthClient } from '@dfinity/auth-client';
import { Principal } from '@dfinity/principal';
import {
  DerivedPublicKey,
  EncryptedVetKey,
  IbeCiphertext,
  IbeIdentity,
  IbeSeed,
  TransportSecretKey
} from '@dfinity/vetkeys';
import { defaultBackendCanisterId, getBackendActor } from './ic/backendClient.js';

const STORAGE_HOST = 'rustshow.vetkeys.host';
const STORAGE_CANISTER_ID = 'rustshow.vetkeys.backendId';
const DEFAULT_HOST = import.meta.env.VITE_IC_HOST || '/api';
const DEFAULT_LOCAL_BACKEND_CANISTER_ID = 'ulvla-h7777-77774-qaacq-cai';
const DEFAULT_CANISTER_ID =
  defaultBackendCanisterId ||
  import.meta.env.CANISTER_ID_BACKEND ||
  import.meta.env.VITE_BACKEND_CANISTER_ID ||
  process.env.CANISTER_ID_BACKEND ||
  DEFAULT_LOCAL_BACKEND_CANISTER_ID;
const DEFAULT_IDP = import.meta.env.VITE_IDENTITY_PROVIDER || 'https://identity.internetcomputer.org';
const DEFAULT_LOCAL_II_CANISTER_ID =
  import.meta.env.CANISTER_ID_INTERNET_IDENTITY ||
  import.meta.env.VITE_LOCAL_II_CANISTER_ID ||
  'uxrrr-q7777-77774-qaaaq-cai';
const DEFAULT_LOCAL_REPLICA_ORIGIN = import.meta.env.VITE_LOCAL_REPLICA_ORIGIN || 'http://127.0.0.1:4943';
const FEATURE_VETKEYS_MESSENGER = 'vetkeys-messenger';
const FEATURE_BUTTONS = [
  {
    id: FEATURE_VETKEYS_MESSENGER,
    name: 'VetKeys 私密消息',
    enabled: true
  }
];

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

function loadStoredValue(key, fallback) {
  if (typeof window === 'undefined') {
    return fallback;
  }
  const value = window.localStorage.getItem(key);
  return value === null ? fallback : value;
}

function loadStoredValueOrFallbackWhenEmpty(key, fallback) {
  const value = loadStoredValue(key, fallback);
  if (typeof value === 'string' && value.trim() === '') {
    return fallback;
  }
  return value;
}

function errorMessage(error) {
  if (error instanceof Error) {
    return error.message;
  }
  return String(error);
}

function nowLabel() {
  return new Date().toLocaleTimeString('zh-CN', { hour12: false });
}

function unwrapResult(result) {
  if (result && typeof result === 'object') {
    if ('Ok' in result) {
      return result.Ok;
    }
    if ('Err' in result) {
      throw new Error(result.Err);
    }
  }
  if (typeof result === 'string') {
    return result;
  }
  throw new Error('后端返回格式不正确。');
}

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
  const trimmed = hex.trim();
  const value = trimmed.startsWith('0x') || trimmed.startsWith('0X') ? trimmed.slice(2) : trimmed;
  if (value.length % 2 !== 0) {
    throw new Error('十六进制字符串长度必须为偶数。');
  }
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < value.length; i += 2) {
    const chunk = value.slice(i, i + 2);
    const byte = Number.parseInt(chunk, 16);
    if (Number.isNaN(byte)) {
      throw new Error(`无效十六进制内容：${chunk}`);
    }
    out[i / 2] = byte;
  }
  return out;
}

function isLocalBackendTarget(host) {
  const value = (host || '').trim();
  if (!value || value === '/api') {
    return true;
  }
  return value.includes('127.0.0.1') || value.includes('localhost');
}

function localIiProviderBaseFromBackendHost(host, iiCanisterId) {
  const value = (host || '').trim();
  const normalizedCanisterId = iiCanisterId.trim();
  if (!normalizedCanisterId) {
    return '';
  }

  const makeLocalIiOrigin = (protocol, port) => `${protocol}//${normalizedCanisterId}.localhost:${port}`;

  if (!value || value === '/api') {
    try {
      const fallbackUrl = new URL(DEFAULT_LOCAL_REPLICA_ORIGIN);
      const port = fallbackUrl.port || (fallbackUrl.protocol === 'https:' ? '443' : '80');
      return makeLocalIiOrigin(fallbackUrl.protocol, port);
    } catch {
      return makeLocalIiOrigin('http:', '4943');
    }
  }
  if (value.startsWith('http://') || value.startsWith('https://')) {
    try {
      const url = new URL(value);
      const port = url.port || (url.protocol === 'https:' ? '443' : '80');
      return makeLocalIiOrigin(url.protocol, port);
    } catch {
      return makeLocalIiOrigin('http:', '4943');
    }
  }
  return makeLocalIiOrigin('http:', '4943');
}

function resolveIiLoginConfig({ backendHost, localIiCanisterId }) {
  if (isLocalBackendTarget(backendHost)) {
    const iiCanisterId = localIiCanisterId.trim();
    if (!iiCanisterId) {
      throw new Error('当前环境判定为本地，但未配置本地 II canister id（请通过环境变量提供）。');
    }
    const iiBase = localIiProviderBaseFromBackendHost(backendHost, iiCanisterId);
    return {
      network: 'local',
      provider: iiBase
    };
  }

  return { network: 'ic', provider: DEFAULT_IDP };
}

export default function App() {
  const [activeFeatureId, setActiveFeatureId] = useState(null);
  const [backendHost, setBackendHost] = useState(() =>
    loadStoredValueOrFallbackWhenEmpty(STORAGE_HOST, DEFAULT_HOST)
  );
  const [backendCanisterId, setBackendCanisterId] = useState(() =>
    loadStoredValueOrFallbackWhenEmpty(STORAGE_CANISTER_ID, DEFAULT_CANISTER_ID)
  );

  const [authClient, setAuthClient] = useState(null);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [principalText, setPrincipalText] = useState('');

  const [receiverPrincipal, setReceiverPrincipal] = useState('');
  const [plainMessage, setPlainMessage] = useState('');
  const [ciphertextOutput, setCiphertextOutput] = useState('');

  const [ciphertextInput, setCiphertextInput] = useState('');
  const [decryptOutput, setDecryptOutput] = useState('');

  const [busy, setBusy] = useState('');
  const [events, setEvents] = useState([
    { id: 1, kind: 'info', time: nowLabel(), text: '仅保留 VetKeys A/B 加密解密流程。' }
  ]);

  function pushEvent(kind, text) {
    const entry = {
      id: Date.now() + Math.floor(Math.random() * 1000),
      kind,
      time: nowLabel(),
      text
    };
    setEvents((prev) => [entry, ...prev].slice(0, 10));
  }

  useEffect(() => {
    window.localStorage.setItem(STORAGE_HOST, backendHost);
  }, [backendHost]);

  useEffect(() => {
    window.localStorage.setItem(STORAGE_CANISTER_ID, backendCanisterId);
  }, [backendCanisterId]);

  useEffect(() => {
    let cancelled = false;
    async function initAuth() {
      const client = await AuthClient.create({
        idleOptions: {
          disableDefaultIdleCallback: true
        }
      });
      if (cancelled) {
        return;
      }
      setAuthClient(client);
      const authenticated = await client.isAuthenticated();
      if (cancelled) {
        return;
      }
      setIsAuthenticated(authenticated);
      if (authenticated) {
        setPrincipalText(client.getIdentity().getPrincipal().toText());
      } else {
        setPrincipalText('');
      }
    }

    initAuth().catch((error) => {
      pushEvent('error', `初始化登录组件失败：${errorMessage(error)}`);
    });

    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (!activeFeatureId) {
      return undefined;
    }
    function onKeyDown(event) {
      if (event.key === 'Escape') {
        setActiveFeatureId(null);
      }
    }
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [activeFeatureId]);

  async function runAction(label, action) {
    setBusy(label);
    try {
      await action();
    } catch (error) {
      pushEvent('error', errorMessage(error));
    } finally {
      setBusy('');
    }
  }

  function requireAuthClient() {
    if (!authClient) {
      throw new Error('登录组件未初始化完成。');
    }
    return authClient;
  }

  function requireIdentity() {
    const client = requireAuthClient();
    if (!isAuthenticated) {
      throw new Error('请先登录。');
    }
    return client.getIdentity();
  }

  async function withActor(action) {
    const identity = requireIdentity();
    const actor = await getBackendActor({
      canisterId: backendCanisterId,
      host: backendHost,
      identity
    });
    return action(actor, identity);
  }

  async function refreshIdentityState(client) {
    const authenticated = await client.isAuthenticated();
    setIsAuthenticated(authenticated);
    setPrincipalText(authenticated ? client.getIdentity().getPrincipal().toText() : '');
  }

  async function onLogin() {
    await runAction('登录中', async () => {
      const client = requireAuthClient();
      const iiLogin = resolveIiLoginConfig({
        backendHost,
        localIiCanisterId: DEFAULT_LOCAL_II_CANISTER_ID
      });
      await new Promise((resolve, reject) => {
        client.login({
          identityProvider: iiLogin.provider,
          onSuccess: () => resolve(),
          onError: (error) => reject(new Error(error || '登录失败'))
        });
      });
      await refreshIdentityState(client);
      pushEvent(
        'ok',
        `登录成功（${iiLogin.network === 'local' ? '本地 II' : 'IC II'}）。`
      );
    });
  }

  async function onLogout() {
    await runAction('退出登录', async () => {
      const client = requireAuthClient();
      await client.logout();
      await refreshIdentityState(client);
      pushEvent('ok', '已退出登录。');
    });
  }

  async function onEncryptForB() {
    await runAction('A 端加密', async () => {
      if (!plainMessage.trim()) {
        throw new Error('请输入要加密的消息。');
      }
      const recipient = Principal.fromText(receiverPrincipal.trim());
      const encrypted = await withActor(async (backend) => {
        const dpkHex = unwrapResult(await backend.ibe_public_key_hex());
        const dpk = DerivedPublicKey.deserialize(hexToBytes(dpkHex));
        const ciphertext = IbeCiphertext.encrypt(
          dpk,
          IbeIdentity.fromPrincipal(recipient),
          textEncoder.encode(plainMessage),
          IbeSeed.random()
        );
        return bytesToHex(ciphertext.serialize());
      });
      setCiphertextOutput(encrypted);
      pushEvent('ok', 'A 端已生成十六进制密文，可复制给 B。');
    });
  }

  async function onDecryptAsB() {
    await runAction('B 端解密', async () => {
      const payload = ciphertextInput.trim();
      if (!payload) {
        throw new Error('请粘贴密文。');
      }
      const plaintext = await withActor(async (backend, identity) => {
        const principal = identity.getPrincipal();
        const dpkHex = unwrapResult(await backend.ibe_public_key_hex());
        const dpk = DerivedPublicKey.deserialize(hexToBytes(dpkHex));

        const transportSecretKey = TransportSecretKey.random();
        const transportPublicKeyHex = bytesToHex(transportSecretKey.publicKeyBytes());
        const encryptedVetKeyHex = unwrapResult(
          await backend.ibe_decryption_key_for_caller_hex(transportPublicKeyHex)
        );

        const encryptedVetKey = EncryptedVetKey.deserialize(hexToBytes(encryptedVetKeyHex));
        const vetKey = encryptedVetKey.decryptAndVerify(
          transportSecretKey,
          dpk,
          principal.toUint8Array()
        );

        const ciphertext = IbeCiphertext.deserialize(hexToBytes(payload));
        const messageBytes = ciphertext.decrypt(vetKey);
        return textDecoder.decode(messageBytes);
      });
      setDecryptOutput(plaintext);
      pushEvent('ok', 'B 端解密成功。');
    });
  }

  return (
    <>
      {!activeFeatureId ? (
        <main className="launcher-root" aria-label="功能入口">
          <div className="feature-button-grid">
            {FEATURE_BUTTONS.map((feature) => (
              <button
                key={feature.id}
                type="button"
                className="feature-launch-button"
                onClick={() => feature.enabled && setActiveFeatureId(feature.id)}
                disabled={!feature.enabled}
                title={feature.name}
              >
                <span>{feature.name}</span>
              </button>
            ))}
          </div>
        </main>
      ) : (
        <div className="feature-overlay" role="dialog" aria-modal="true">
          <div className="feature-overlay-topbar">
            <button
              type="button"
              className="feature-overlay-close"
              onClick={() => setActiveFeatureId(null)}
            >
              返回功能列表
            </button>
            <span className="feature-overlay-title">
              {activeFeatureId === FEATURE_VETKEYS_MESSENGER ? 'VetKeys 私密消息' : '功能'}
            </span>
          </div>
          <div className="feature-overlay-scroll">
            <div className="app-shell">
      <header className="hero reveal reveal-1">
        <p className="eyebrow">VETKEYS PRIVATE MESSAGE DEMO</p>
        <h1>RustShow Messenger</h1>
        <p className="subtitle">A 使用 II 登录后加密给 B；B 使用 II 登录后粘贴密文解密</p>
        <div className="chip-row">
          <span className="chip">Internet Identity</span>
          <span className="chip">VetKeys IBE</span>
          <span className="chip">End-to-End Style</span>
        </div>
      </header>

      <section className="status-panel reveal reveal-2">
        <span className={`status-dot${busy ? ' is-busy' : ''}`} />
        <span>{busy ? `执行中：${busy}` : isAuthenticated ? `II 已登录：${principalText}` : 'II 未登录'}</span>
      </section>

      <main className="grid">
        <section className="card card-wide reveal reveal-2 login-only-card">
          <div className="button-row">
            <button
              type="button"
              onClick={isAuthenticated ? onLogout : onLogin}
              disabled={Boolean(busy)}
              className={isAuthenticated ? 'button-secondary' : undefined}
            >
              {isAuthenticated ? 'II 登出' : 'II 登录'}
            </button>
          </div>
        </section>

        <section className="card reveal reveal-3">
          <h2>A 端加密</h2>
          <p className="card-help">A 使用 II 登录后填写 B 的 Principal 与消息，生成密文发给 B。</p>
          <div className="field">
            <label htmlFor="receiverPrincipal">B Principal</label>
            <input
              id="receiverPrincipal"
              value={receiverPrincipal}
              onChange={(event) => setReceiverPrincipal(event.target.value)}
              placeholder="例如：rdmx6-jaaaa-aaaaa-aaadq-cai"
            />
          </div>
          <div className="field">
            <label htmlFor="plainMessage">消息</label>
            <textarea
              id="plainMessage"
              value={plainMessage}
              onChange={(event) => setPlainMessage(event.target.value)}
              rows={5}
              placeholder="输入要加密给 B 的消息"
            />
          </div>
          <div className="button-row">
            <button type="button" onClick={onEncryptForB} disabled={Boolean(busy)}>
              生成密文
            </button>
          </div>
          <div className="output">
            <span className="output-label">Ciphertext (Hex)</span>
            <code>{ciphertextOutput || '尚未生成'}</code>
          </div>
        </section>

        <section className="card reveal reveal-4">
          <h2>B 端解密</h2>
          <p className="card-help">B 使用 II 登录后粘贴密文并解密，只有匹配 Principal 的 B 能成功。</p>
          <div className="field">
            <label htmlFor="ciphertextInput">密文</label>
            <textarea
              id="ciphertextInput"
              value={ciphertextInput}
              onChange={(event) => setCiphertextInput(event.target.value)}
              rows={5}
              placeholder="粘贴 A 发来的十六进制密文"
            />
          </div>
          <div className="button-row">
            <button type="button" onClick={onDecryptAsB} disabled={Boolean(busy)}>
              解密
            </button>
          </div>
          <div className="output">
            <span className="output-label">Plaintext</span>
            <code>{decryptOutput || '尚未解密'}</code>
          </div>
        </section>

        <section className="card card-wide reveal reveal-4">
          <h2>事件流</h2>
          <p className="card-help">最近操作和错误信息。</p>
          <ul className="event-list">
            {events.map((event) => (
              <li key={event.id} className={`event-item event-${event.kind}`}>
                <span className="event-time">{event.time}</span>
                <span>{event.text}</span>
              </li>
            ))}
          </ul>
        </section>
      </main>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
