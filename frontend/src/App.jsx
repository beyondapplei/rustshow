import { useEffect, useState } from 'react';
import { AuthClient } from '@dfinity/auth-client';
import { Principal } from '@dfinity/principal';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
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
const DEFAULT_VETKD_KEY_NAME = 'test_key_1';
const DEFAULT_VETKD_CONTEXT = 'motoko-show';
const DEFAULT_ECDSA_KEY_NAME_LOCAL = 'dfx_test_key';
const DEFAULT_ECDSA_KEY_NAME_IC = 'test_key_1';
const CIPHER_PACKAGE_MAGIC = Uint8Array.from([0x56, 0x4b, 0x44, 0x01]); // "VKD" + version
const FEATURE_VETKEYS_MESSENGER = 'vetkeys-messenger';
const FEATURE_THRESHOLD_ECDSA = 'threshold-ecdsa';
const FEATURE_MULTI_CHAIN_WALLET = 'ii-multi-chain-wallet';
const FEATURE_BUTTONS = [
  {
    id: FEATURE_VETKEYS_MESSENGER,
    name: 'VetKeys 私密消息',
    enabled: true
  },
  {
    id: FEATURE_THRESHOLD_ECDSA,
    name: 'Threshold ECDSA (ETH 验签)',
    enabled: true
  },
  {
    id: FEATURE_MULTI_CHAIN_WALLET,
    name: 'II 多链钱包（演示）',
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

function bytesEqual(left, right) {
  if (left.length !== right.length) {
    return false;
  }
  for (let i = 0; i < left.length; i += 1) {
    if (left[i] !== right[i]) {
      return false;
    }
  }
  return true;
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

function concatBytes(...chunks) {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function defaultEcdsaKeyNameForHost(host) {
  return isLocalBackendTarget(host) ? DEFAULT_ECDSA_KEY_NAME_LOCAL : DEFAULT_ECDSA_KEY_NAME_IC;
}

function encodeCipherPackage({ recipientBytes, derivedPublicKeyBytes, ciphertextBytes }) {
  if (recipientBytes.length > 255) {
    throw new Error('接收者 principal 编码过长。');
  }
  if (derivedPublicKeyBytes.length > 65535) {
    throw new Error('VetKD 公钥长度异常。');
  }
  const dpkLength = derivedPublicKeyBytes.length;
  const header = Uint8Array.from([
    ...CIPHER_PACKAGE_MAGIC,
    recipientBytes.length,
    (dpkLength >> 8) & 0xff,
    dpkLength & 0xff
  ]);
  return concatBytes(header, recipientBytes, derivedPublicKeyBytes, ciphertextBytes);
}

function decodeCipherPackage(bytes) {
  if (bytes.length < 7 || !bytesEqual(bytes.subarray(0, 4), CIPHER_PACKAGE_MAGIC)) {
    return {
      ok: true,
      packaged: false,
      ciphertextBytes: Uint8Array.from(bytes)
    };
  }
  const recipientLength = bytes[4];
  const dpkLength = (bytes[5] << 8) | bytes[6];
  const payloadOffset = 7;
  const minLength = payloadOffset + recipientLength + dpkLength + 1;
  if (bytes.length < minLength) {
    return { ok: false, error: 'invalid_package' };
  }
  const recipientStart = payloadOffset;
  const recipientEnd = recipientStart + recipientLength;
  const dpkStart = recipientEnd;
  const dpkEnd = dpkStart + dpkLength;
  return {
    ok: true,
    packaged: true,
    recipientBytes: Uint8Array.from(bytes.subarray(recipientStart, recipientEnd)),
    derivedPublicKeyBytes: Uint8Array.from(bytes.subarray(dpkStart, dpkEnd)),
    ciphertextBytes: Uint8Array.from(bytes.subarray(dpkEnd))
  };
}

function normalizeEthAddress(address) {
  const trimmed = address.trim();
  const value = trimmed.startsWith('0x') || trimmed.startsWith('0X') ? trimmed.slice(2) : trimmed;
  if (!/^[0-9a-fA-F]{40}$/.test(value)) {
    throw new Error('ETH 地址格式无效（需要 20 字节 hex）。');
  }
  return `0x${value.toLowerCase()}`;
}

function normalizeSecp256k1CompressedPublicKey(bytes) {
  if (bytes.length === 33 && (bytes[0] === 2 || bytes[0] === 3)) {
    return bytes;
  }
  if (bytes.length === 65 && bytes[0] === 4) {
    return secp256k1.Point.fromHex(bytes).toRawBytes(true);
  }
  throw new Error('无效的 secp256k1 公钥格式（需要压缩 33 字节或未压缩 65 字节 SEC1）。');
}

function secp256k1CompressedPublicKeyToEthAddress(bytes) {
  const compressed = normalizeSecp256k1CompressedPublicKey(bytes);
  const uncompressed = secp256k1.Point.fromHex(compressed).toRawBytes(false);
  const digest = keccak_256(uncompressed.slice(1));
  return `0x${bytesToHex(digest.slice(-20))}`;
}

function ethereumPersonalMessageHash(messageText) {
  const messageBytes = textEncoder.encode(messageText);
  const prefix = `\x19Ethereum Signed Message:\n${messageBytes.length}`;
  return keccak_256(concatBytes(textEncoder.encode(prefix), messageBytes));
}

function parseEthereumSignatureHex(signatureHex) {
  const bytes = hexToBytes(signatureHex);
  if (bytes.length === 64) {
    return { compact: bytes, recoveryCandidates: [0, 1, 2, 3] };
  }
  if (bytes.length !== 65) {
    throw new Error('ETH 签名长度必须为 64 或 65 字节（r||s 或 r||s||v）。');
  }
  const compact = bytes.slice(0, 64);
  const v = bytes[64];
  if (v === 27 || v === 28) {
    return { compact, recoveryCandidates: [v - 27, v - 27 + 2] };
  }
  if (v === 0 || v === 1) {
    return { compact, recoveryCandidates: [v, v + 2] };
  }
  throw new Error('ETH 签名 v 值无效（仅支持 27/28 或 0/1）。');
}

function buildEthereumSignatureHex(compactSignatureBytes, recoveryId) {
  return bytesToHex(concatBytes(compactSignatureBytes, Uint8Array.of(27 + (recoveryId % 2))));
}

function recoverCompressedPublicKey(messageHash, compactSignatureBytes, recoveryId) {
  return secp256k1.Signature.fromCompact(compactSignatureBytes)
    .addRecoveryBit(recoveryId)
    .recoverPublicKey(messageHash)
    .toRawBytes(true);
}

function findRecoveryIdForPublicKey(messageHash, compactSignatureBytes, expectedCompressedPublicKey) {
  const expectedHex = bytesToHex(expectedCompressedPublicKey);
  for (const recoveryId of [0, 1, 2, 3]) {
    try {
      if (bytesToHex(recoverCompressedPublicKey(messageHash, compactSignatureBytes, recoveryId)) === expectedHex) {
        return recoveryId;
      }
    } catch {
      // continue
    }
  }
  throw new Error('无法从签名恢复出与 A 公钥匹配的 recovery id。');
}

function isWalletEvmChain(networkId) {
  return networkId === 'eth' || networkId === 'sepolia' || networkId === 'base';
}

function shortText(value, head = 10, tail = 8) {
  const text = String(value ?? '');
  if (!text) {
    return '';
  }
  if (text.length <= head + tail + 3) {
    return text;
  }
  return `${text.slice(0, head)}...${text.slice(-tail)}`;
}

function unwrapOpt(value) {
  if (Array.isArray(value)) {
    return value.length > 0 ? value[0] : null;
  }
  return value ?? null;
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

  const [ecdsaSignMessage, setEcdsaSignMessage] = useState('');
  const [ecdsaMessageHashHex, setEcdsaMessageHashHex] = useState('');
  const [ecdsaSignatureHex, setEcdsaSignatureHex] = useState('');
  const [ecdsaPublicKeyHex, setEcdsaPublicKeyHex] = useState('');
  const [ecdsaEthAddress, setEcdsaEthAddress] = useState('');

  const [ecdsaVerifyMessage, setEcdsaVerifyMessage] = useState('');
  const [ecdsaVerifySignatureHex, setEcdsaVerifySignatureHex] = useState('');
  const [ecdsaVerifyEthAddress, setEcdsaVerifyEthAddress] = useState('');
  const [ecdsaVerifyResult, setEcdsaVerifyResult] = useState('');

  const [walletNetworks, setWalletNetworks] = useState([]);
  const [walletChainId, setWalletChainId] = useState('eth');
  const [walletOverview, setWalletOverview] = useState(null);
  const [walletOverviewError, setWalletOverviewError] = useState('');

  const [busy, setBusy] = useState('');
  const [events, setEvents] = useState([
    { id: 1, kind: 'info', time: nowLabel(), text: '已集成 VetKeys、Threshold ECDSA 与钱包演示功能。' }
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

  async function withAnonymousActor(action) {
    const actor = await getBackendActor({
      canisterId: backendCanisterId,
      host: backendHost
    });
    return action(actor);
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

  async function loadWalletNetworks() {
    const networks = await withAnonymousActor(async (backend) => {
      if (typeof backend.wallet_networks !== 'function') {
        throw new Error('当前后端未暴露 wallet_networks（请重新部署 backend）。');
      }
      return backend.wallet_networks();
    });
    setWalletNetworks(Array.isArray(networks) ? networks : []);
    setWalletChainId((prev) => {
      if (Array.isArray(networks) && networks.some((item) => item.id === prev)) {
        return prev;
      }
      return Array.isArray(networks) && networks[0]?.id ? networks[0].id : 'eth';
    });
    return networks;
  }

  async function refreshWalletOverview(targetChainId = walletChainId) {
    if (!targetChainId) {
      setWalletOverview(null);
      setWalletOverviewError('');
      return;
    }
    if (!isAuthenticated) {
      setWalletOverview(null);
      setWalletOverviewError('请先登录 II 后查看钱包总览。');
      return;
    }

    await runAction('钱包总览', async () => {
      const result = await withActor(async (backend) => {
        if (typeof backend.wallet_overview !== 'function') {
          throw new Error('当前后端未暴露 wallet_overview（请重新部署 backend）。');
        }
        return unwrapResult(await backend.wallet_overview(targetChainId, [], []));
      });
      setWalletOverview(result);
      setWalletOverviewError('');
      pushEvent('ok', `钱包总览已刷新：${targetChainId}`);
    });
  }

  useEffect(() => {
    if (activeFeatureId !== FEATURE_MULTI_CHAIN_WALLET) {
      return;
    }
    loadWalletNetworks().catch((error) => {
      setWalletNetworks([]);
      setWalletOverview(null);
      setWalletOverviewError(errorMessage(error));
      pushEvent('error', `加载钱包网络列表失败：${errorMessage(error)}`);
    });
  }, [activeFeatureId, backendCanisterId, backendHost]);

  useEffect(() => {
    if (activeFeatureId !== FEATURE_MULTI_CHAIN_WALLET) {
      return;
    }
    if (!walletChainId) {
      return;
    }
    if (!isAuthenticated) {
      setWalletOverview(null);
      setWalletOverviewError('请先登录 II 后查看钱包总览。');
      return;
    }
    refreshWalletOverview(walletChainId).catch((error) => {
      setWalletOverview(null);
      setWalletOverviewError(errorMessage(error));
      pushEvent('error', `读取钱包总览失败：${errorMessage(error)}`);
    });
  }, [activeFeatureId, walletChainId, isAuthenticated, principalText]);

  async function onEncryptForB() {
    await runAction('A 端加密', async () => {
      if (!plainMessage.trim()) {
        throw new Error('请输入要加密的消息。');
      }
      const recipient = Principal.fromText(receiverPrincipal.trim());
      const encrypted = await withActor(async (backend) => {
        const keyName = DEFAULT_VETKD_KEY_NAME;
        const context = DEFAULT_VETKD_CONTEXT;
        const dpkHex =
          typeof backend.vetkdPublicKeyExample === 'function'
            ? unwrapResult(await backend.vetkdPublicKeyExample(keyName, context))
            : unwrapResult(await backend.ibe_public_key_hex());

        const dpkBytes = hexToBytes(dpkHex);
        const dpk = DerivedPublicKey.deserialize(dpkBytes);
        const recipientBytes = recipient.toUint8Array();
        const ciphertext = IbeCiphertext.encrypt(
          dpk,
          IbeIdentity.fromPrincipal(recipient),
          textEncoder.encode(plainMessage),
          IbeSeed.random()
        );
        const ciphertextBytes = Uint8Array.from(ciphertext.serialize());
        const packaged = encodeCipherPackage({
          recipientBytes,
          derivedPublicKeyBytes: dpkBytes,
          ciphertextBytes
        });
        return bytesToHex(packaged);
      });
      setCiphertextOutput(encrypted);
      setCiphertextInput(encrypted);
      setDecryptOutput('');
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
        const inputBytes = hexToBytes(payload);
        const decoded = decodeCipherPackage(inputBytes);
        if (!decoded.ok) {
          throw new Error('密文打包格式错误。');
        }

        const keyName = DEFAULT_VETKD_KEY_NAME;
        const context = DEFAULT_VETKD_CONTEXT;
        const dpkHex =
          typeof backend.vetkdPublicKeyExample === 'function'
            ? unwrapResult(await backend.vetkdPublicKeyExample(keyName, context))
            : unwrapResult(await backend.ibe_public_key_hex());
        const runtimeDpkBytes = hexToBytes(dpkHex);

        const transportSecretKey = TransportSecretKey.random();
        const transportPublicKeyBytes = Uint8Array.from(transportSecretKey.publicKeyBytes());
        const encryptedVetKeyHex =
          typeof backend.vetkdDeriveKeyExample === 'function'
            ? unwrapResult(
                await backend.vetkdDeriveKeyExample(Array.from(transportPublicKeyBytes), keyName, context)
              )
            : unwrapResult(await backend.ibe_decryption_key_for_caller_hex(bytesToHex(transportPublicKeyBytes)));

        const encryptedVetKey = EncryptedVetKey.deserialize(hexToBytes(encryptedVetKeyHex));
        let callerInputBytes = principal.toUint8Array();
        if (typeof backend.vetkdCallerInputHex === 'function') {
          callerInputBytes = hexToBytes(await backend.vetkdCallerInputHex());
          if (!bytesEqual(callerInputBytes, principal.toUint8Array())) {
            throw new Error('当前前端显示身份与后端调用身份不一致，请重新登录后重试。');
          }
        }

        const effectiveDpkBytes = decoded.packaged ? decoded.derivedPublicKeyBytes : runtimeDpkBytes;
        const effectiveCiphertextBytes = decoded.packaged ? decoded.ciphertextBytes : decoded.ciphertextBytes;
        if (decoded.packaged && !bytesEqual(decoded.recipientBytes, callerInputBytes)) {
          let target = '';
          try {
            target = Principal.fromUint8Array(decoded.recipientBytes).toText();
          } catch {
            target = bytesToHex(decoded.recipientBytes);
          }
          throw new Error(`密文目标账号与当前登录账号不一致（target=${target} current=${principal.toText()}）。`);
        }
        if (decoded.packaged && !bytesEqual(runtimeDpkBytes, decoded.derivedPublicKeyBytes)) {
          throw new Error('密文与当前链环境不匹配（可能本地链已重启），请 A 重新加密。');
        }

        const dpk = DerivedPublicKey.deserialize(effectiveDpkBytes);
        const vetKey = encryptedVetKey.decryptAndVerify(
          transportSecretKey,
          dpk,
          callerInputBytes
        );

        const ciphertext = IbeCiphertext.deserialize(effectiveCiphertextBytes);
        const messageBytes = ciphertext.decrypt(vetKey);
        return textDecoder.decode(messageBytes);
      });
      setDecryptOutput(plaintext);
      pushEvent('ok', 'B 端解密成功。');
    });
  }

  async function onEcdsaSignAsA() {
    await runAction('A 端 ECDSA 签名', async () => {
      if (!ecdsaSignMessage.trim()) {
        throw new Error('请输入要签名的消息。');
      }

      const messageHash = ethereumPersonalMessageHash(ecdsaSignMessage);
      const messageHashHex = bytesToHex(messageHash);
      const keyName = defaultEcdsaKeyNameForHost(backendHost);

      const { publicKeyHex, ethAddress, signatureHex } = await withActor(async (backend) => {
        const [publicKeySec1Hex, compactSignatureHex] =
          typeof backend.ecdsaPublicKeyExample === 'function' &&
          typeof backend.ecdsaSignMessageHashExample === 'function'
            ? await Promise.all([
                unwrapResult(await backend.ecdsaPublicKeyExample(keyName)),
                unwrapResult(await backend.ecdsaSignMessageHashExample(Array.from(messageHash), keyName))
              ])
            : await Promise.all([
                unwrapResult(await backend.ecdsa_public_key_for_caller_hex()),
                unwrapResult(await backend.ecdsa_sign_hash_hex_for_caller(messageHashHex))
              ]);

        const publicKeyBytes = normalizeSecp256k1CompressedPublicKey(hexToBytes(publicKeySec1Hex));
        const compactSignatureBytes = hexToBytes(compactSignatureHex);
        if (compactSignatureBytes.length !== 64) {
          throw new Error('后端返回的 ECDSA 签名长度不是 64 字节。');
        }

        const recoveryId = findRecoveryIdForPublicKey(messageHash, compactSignatureBytes, publicKeyBytes);
        return {
          publicKeyHex: bytesToHex(publicKeyBytes),
          ethAddress: secp256k1CompressedPublicKeyToEthAddress(publicKeyBytes),
          signatureHex: buildEthereumSignatureHex(compactSignatureBytes, recoveryId)
        };
      });

      setEcdsaMessageHashHex(messageHashHex);
      setEcdsaPublicKeyHex(publicKeyHex);
      setEcdsaEthAddress(ethAddress);
      setEcdsaSignatureHex(signatureHex);

      setEcdsaVerifyMessage(ecdsaSignMessage);
      setEcdsaVerifyEthAddress(ethAddress);
      setEcdsaVerifySignatureHex(signatureHex);
      setEcdsaVerifyResult('');

      pushEvent('ok', `A 端 Threshold ECDSA 签名成功（${keyName}），已生成 ETH 地址与签名。`);
    });
  }

  async function onEcdsaVerifyAsB() {
    await runAction('B 端 ETH 验签', async () => {
      if (!ecdsaVerifyMessage.trim()) {
        throw new Error('请输入待验签原文。');
      }
      if (!ecdsaVerifyEthAddress.trim()) {
        throw new Error('请填写 A 的 ETH 地址。');
      }
      if (!ecdsaVerifySignatureHex.trim()) {
        throw new Error('请填写签名（hex）。');
      }

      const expectedAddress = normalizeEthAddress(ecdsaVerifyEthAddress);
      const messageHash = ethereumPersonalMessageHash(ecdsaVerifyMessage);
      const { compact, recoveryCandidates } = parseEthereumSignatureHex(ecdsaVerifySignatureHex);

      let ok = false;
      for (const recoveryId of recoveryCandidates) {
        try {
          const recoveredPublicKey = recoverCompressedPublicKey(messageHash, compact, recoveryId);
          const recoveredAddress = secp256k1CompressedPublicKeyToEthAddress(recoveredPublicKey);
          const verified = secp256k1.verify(compact, messageHash, recoveredPublicKey, {
            prehash: false,
            lowS: false
          });
          if (verified && normalizeEthAddress(recoveredAddress) === expectedAddress) {
            ok = true;
            break;
          }
        } catch {
          // Try next candidate recovery id.
        }
      }

      setEcdsaVerifyResult(ok ? '验签通过' : '验签失败');
      pushEvent(ok ? 'ok' : 'error', ok ? 'B 端 ETH 验签通过。' : 'B 端 ETH 验签失败。');
    });
  }

  const walletActiveNetwork =
    walletNetworks.find((network) => network.id === walletChainId) ?? walletNetworks[0] ?? null;
  const walletOverviewPublicKeyHex = unwrapOpt(walletOverview?.evmPublicKeyHex) || '';
  const walletOverviewAddress = unwrapOpt(walletOverview?.evmAddress) || '';
  const walletDefaultRpcUrl = unwrapOpt(walletActiveNetwork?.defaultRpcUrl) || '';
  const walletOverviewDerivedAddress =
    walletOverviewAddress ||
    (walletOverviewPublicKeyHex && isWalletEvmChain(walletOverview?.selectedNetwork)
      ? (() => {
          try {
            return secp256k1CompressedPublicKeyToEthAddress(hexToBytes(walletOverviewPublicKeyHex));
          } catch {
            return '';
          }
        })()
      : '');
  const walletPrimaryAmountDisplay = walletOverview?.primaryAvailable
    ? `${walletOverview.primaryAmount} ${walletOverview.primarySymbol || ''}`.trim()
    : '未接入';

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
              {activeFeatureId === FEATURE_VETKEYS_MESSENGER
                ? 'VetKeys 私密消息'
                : activeFeatureId === FEATURE_THRESHOLD_ECDSA
                  ? 'Threshold ECDSA (ETH 验签)'
                  : activeFeatureId === FEATURE_MULTI_CHAIN_WALLET
                    ? 'II 多链钱包（演示）'
                  : '功能'}
            </span>
          </div>
          <div className="feature-overlay-scroll">
            {activeFeatureId === FEATURE_VETKEYS_MESSENGER ? (
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
            ) : activeFeatureId === FEATURE_THRESHOLD_ECDSA ? (
              <div className="app-shell">
                <header className="hero reveal reveal-1">
                  <p className="eyebrow">THRESHOLD ECDSA ETH SIGNATURE DEMO</p>
                  <h1>RustShow ECDSA</h1>
                  <p className="subtitle">
                    A 使用 II 登录后做 Threshold ECDSA(secp256k1) 签名；B 仅用 ETH 地址 + 原文 + 签名验签
                  </p>
                  <div className="chip-row">
                    <span className="chip">Internet Identity</span>
                    <span className="chip">Threshold ECDSA</span>
                    <span className="chip">ETH Personal Sign</span>
                  </div>
                </header>

                <section className="status-panel reveal reveal-2">
                  <span className={`status-dot${busy ? ' is-busy' : ''}`} />
                  <span>
                    {busy
                      ? `执行中：${busy}`
                      : isAuthenticated
                        ? `II 已登录：${principalText}`
                        : 'II 未登录'}
                  </span>
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
                    <h2>A 端签名</h2>
                    <p className="card-help">
                      A 登录后输入消息。前端按 ETH `personal_sign` 规则做哈希，再由后端 Threshold ECDSA
                      (secp256k1) 对哈希签名。
                    </p>
                    <div className="field">
                      <label htmlFor="ecdsaSignMessage">消息</label>
                      <textarea
                        id="ecdsaSignMessage"
                        value={ecdsaSignMessage}
                        onChange={(event) => setEcdsaSignMessage(event.target.value)}
                        rows={5}
                        placeholder="A 输入要签名的消息"
                      />
                    </div>
                    <div className="button-row">
                      <button type="button" onClick={onEcdsaSignAsA} disabled={Boolean(busy)}>
                        生成签名
                      </button>
                    </div>
                    <div className="output">
                      <span className="output-label">A ETH Address</span>
                      <code>{ecdsaEthAddress || '尚未生成'}</code>
                    </div>
                    <div className="output">
                      <span className="output-label">A Public Key (Hex, secp256k1 compressed)</span>
                      <code>{ecdsaPublicKeyHex || '尚未生成'}</code>
                    </div>
                    <div className="output">
                      <span className="output-label">Message Hash (ETH personal_sign / keccak256)</span>
                      <code>{ecdsaMessageHashHex || '尚未生成'}</code>
                    </div>
                    <div className="output">
                      <span className="output-label">Signature (Hex, r||s||v)</span>
                      <code>{ecdsaSignatureHex || '尚未生成'}</code>
                    </div>
                  </section>

                  <section className="card reveal reveal-4">
                    <h2>B 端验签</h2>
                    <p className="card-help">
                      B 只需要 A 的 ETH 地址、原文和签名（r||s||v hex），前端本地恢复公钥并验证。
                    </p>
                    <div className="field">
                      <label htmlFor="ecdsaVerifyEthAddress">A ETH 地址</label>
                      <textarea
                        id="ecdsaVerifyEthAddress"
                        value={ecdsaVerifyEthAddress}
                        onChange={(event) => setEcdsaVerifyEthAddress(event.target.value)}
                        rows={2}
                        placeholder="例如：0x1234..."
                      />
                    </div>
                    <div className="field">
                      <label htmlFor="ecdsaVerifyMessage">原文消息</label>
                      <textarea
                        id="ecdsaVerifyMessage"
                        value={ecdsaVerifyMessage}
                        onChange={(event) => setEcdsaVerifyMessage(event.target.value)}
                        rows={4}
                        placeholder="粘贴 A 提供的原消息"
                      />
                    </div>
                    <div className="field">
                      <label htmlFor="ecdsaVerifySignatureHex">签名（Hex）</label>
                      <textarea
                        id="ecdsaVerifySignatureHex"
                        value={ecdsaVerifySignatureHex}
                        onChange={(event) => setEcdsaVerifySignatureHex(event.target.value)}
                        rows={4}
                        placeholder="粘贴 A 的 ETH 签名（r||s||v hex）"
                      />
                    </div>
                    <div className="button-row">
                      <button type="button" onClick={onEcdsaVerifyAsB} disabled={Boolean(busy)}>
                        验签
                      </button>
                    </div>
                    <div className="output">
                      <span className="output-label">Verify Result</span>
                      <code>{ecdsaVerifyResult || '尚未验签'}</code>
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
            ) : activeFeatureId === FEATURE_MULTI_CHAIN_WALLET ? (
              <div className="app-shell">
                <header className="hero reveal reveal-1">
                  <p className="eyebrow">II MULTI-CHAIN WALLET SHOWCASE</p>
                  <h1>RustShow Wallet</h1>
                  <p className="subtitle">
                    对齐 motokoshow 的钱包首页能力：链切换 + 钱包总览（当前重点接入 EVM 链钥公钥读取）
                  </p>
                  <div className="chip-row">
                    <span className="chip">Internet Identity</span>
                    <span className="chip">Multi-Chain Wallet UI</span>
                    <span className="chip">Chain-Key ECDSA</span>
                  </div>
                </header>

                <section className="status-panel reveal reveal-2">
                  <span className={`status-dot${busy ? ' is-busy' : ''}`} />
                  <span>
                    {busy
                      ? `执行中：${busy}`
                      : isAuthenticated
                        ? `II 已登录：${principalText}`
                        : 'II 未登录'}
                  </span>
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
                    <h2>链选择</h2>
                    <p className="card-help">后端 `wallet_networks` 返回的钱包网络列表（对齐 motokoshow）。</p>
                    <div className="field">
                      <label htmlFor="walletChainId">网络</label>
                      <select
                        id="walletChainId"
                        value={walletChainId}
                        onChange={(event) => {
                          setWalletChainId(event.target.value);
                          setWalletOverviewError('');
                        }}
                        disabled={Boolean(busy) || walletNetworks.length === 0}
                      >
                        {walletNetworks.length === 0 ? (
                          <option value="">暂无网络（请刷新）</option>
                        ) : (
                          walletNetworks.map((network) => (
                            <option key={network.id} value={network.id}>
                              {network.name} ({network.id})
                            </option>
                          ))
                        )}
                      </select>
                    </div>
                    <div className="button-row">
                      <button
                        type="button"
                        onClick={() => void loadWalletNetworks()}
                        disabled={Boolean(busy)}
                      >
                        刷新网络列表
                      </button>
                      <button
                        type="button"
                        onClick={() => void refreshWalletOverview(walletChainId)}
                        disabled={Boolean(busy) || !walletChainId}
                      >
                        刷新钱包总览
                      </button>
                    </div>
                    <ul className="kv-list">
                      <li>
                        <span>当前链</span>
                        <code>{walletActiveNetwork ? `${walletActiveNetwork.name} (${walletActiveNetwork.id})` : '-'}</code>
                      </li>
                      <li>
                        <span>类型</span>
                        <code>{walletActiveNetwork?.kind || '-'}</code>
                      </li>
                      <li>
                        <span>主资产</span>
                        <code>{walletActiveNetwork?.primarySymbol || '-'}</code>
                      </li>
                      <li>
                        <span>默认 RPC</span>
                        <code>{walletDefaultRpcUrl || '-'}</code>
                      </li>
                    </ul>
                  </section>

                  <section className="card reveal reveal-4">
                    <h2>钱包总览</h2>
                    <p className="card-help">
                      `wallet_overview` 返回当前 caller 的链上钱包基础信息。当前优先接入 EVM 链公钥读取。
                    </p>
                    <div className="output">
                      <span className="output-label">Caller Principal</span>
                      <code>{walletOverview?.callerPrincipalText || principalText || '未登录'}</code>
                    </div>
                    <div className="output">
                      <span className="output-label">Selected Network</span>
                      <code>{walletOverview?.selectedNetwork || walletChainId || '-'}</code>
                    </div>
                    <div className="output">
                      <span className="output-label">Wallet Address</span>
                      <code>{walletOverviewDerivedAddress || '当前链未接入地址生成'}</code>
                    </div>
                    <div className="output">
                      <span className="output-label">Primary Balance</span>
                      <code>{walletPrimaryAmountDisplay}</code>
                    </div>
                    <div className="output">
                      <span className="output-label">Public Key (Hex)</span>
                      <code>{walletOverviewPublicKeyHex || '当前链未返回公钥'}</code>
                    </div>
                    <div className="output">
                      <span className="output-label">Overview Error</span>
                      <code>{walletOverviewError || '无'}</code>
                    </div>
                  </section>

                  <section className="card card-wide reveal reveal-4">
                    <h2>功能说明（钱包）</h2>
                    <p className="card-help">
                      当前为 Rust 版钱包首页演示：支持多链列表与钱包总览结构；EVM 链（ETH/Sepolia/Base）展示链钥公钥，
                      地址由前端根据 secp256k1 公钥推导。发送/余额/多资产明细留作下一步接入。
                    </p>
                    <ul className="kv-list">
                      <li>
                        <span>支持网络数量</span>
                        <code>{walletNetworks.length}</code>
                      </li>
                      <li>
                        <span>EVM 地址推导</span>
                        <code>{walletOverviewDerivedAddress ? shortText(walletOverviewDerivedAddress) : '未生成'}</code>
                      </li>
                      <li>
                        <span>后端方法</span>
                        <code>wallet_networks / wallet_overview</code>
                      </li>
                    </ul>
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
            ) : null}
          </div>
        </div>
      )}
    </>
  );
}
