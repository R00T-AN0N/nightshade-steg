const PBKDF2_ITERATIONS = 600_000;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const AES_KEY_BITS = 256;

const utf8 = new TextEncoder();
const utf8Decoder = new TextDecoder();

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function ensureCrypto(): Crypto {
  if (!globalThis.crypto?.subtle) {
    throw new Error('Web Crypto is unavailable. Open this site in a secure browser context (HTTPS or localhost).');
  }
  return globalThis.crypto;
}

function normalizeBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const copy = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  copy.set(bytes);
  return copy;
}

async function deriveKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
  const cryptoApi = ensureCrypto();
  if (!password) throw new Error('A password is required.');

  const passwordKey = await cryptoApi.subtle.importKey(
    'raw',
    utf8.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return cryptoApi.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: normalizeBytes(salt),
      iterations: PBKDF2_ITERATIONS,
      hash: 'SHA-256',
    },
    passwordKey,
    { name: 'AES-GCM', length: AES_KEY_BITS },
    false,
    ['encrypt', 'decrypt']
  );
}

export interface EncryptionEnvelope {
  salt: Uint8Array;
  iv: Uint8Array;
  ciphertext: Uint8Array;
  fingerprint: string;
}

export async function encryptBytes(data: Uint8Array, password: string, aad?: Uint8Array): Promise<EncryptionEnvelope> {
  const cryptoApi = ensureCrypto();
  const salt = new Uint8Array(new ArrayBuffer(SALT_BYTES));
  const iv = new Uint8Array(new ArrayBuffer(IV_BYTES));
  cryptoApi.getRandomValues(salt);
  cryptoApi.getRandomValues(iv);
  const key = await deriveKey(password, salt);
  const normalizedAad = aad ? normalizeBytes(aad) : undefined;
  const ciphertext = new Uint8Array(await cryptoApi.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: normalizedAad },
    key,
    normalizeBytes(data)
  ));

  return {
    salt,
    iv,
    ciphertext,
    fingerprint: bytesToHex(salt.slice(0, 4)),
  };
}

export async function decryptBytes(
  ciphertext: Uint8Array,
  password: string,
  salt: Uint8Array,
  iv: Uint8Array,
  aad?: Uint8Array
): Promise<Uint8Array> {
  const cryptoApi = ensureCrypto();
  const key = await deriveKey(password, salt);
  const normalizedCiphertext = normalizeBytes(ciphertext);
  const normalizedIv = normalizeBytes(iv);
  const normalizedAad = aad ? normalizeBytes(aad) : undefined;
  try {
    return new Uint8Array(await cryptoApi.subtle.decrypt(
      { name: 'AES-GCM', iv: normalizedIv, additionalData: normalizedAad },
      key,
      normalizedCiphertext
    ));
  } catch {
    throw new Error('Authentication failed. Check the password or verify that the Nightshade file was not modified.');
  }
}

export function bytesToUtf8(bytes: Uint8Array): string {
  return utf8Decoder.decode(bytes);
}

export function utf8ToBytes(value: string): Uint8Array {
  return utf8.encode(value);
}

export { PBKDF2_ITERATIONS, SALT_BYTES, IV_BYTES };
