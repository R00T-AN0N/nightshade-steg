import { bytesToUtf8, decryptBytes, encryptBytes, utf8ToBytes } from './crypto.js';

const MAGIC = new Uint8Array([0x4e, 0x53, 0x54, 0x47]); // NSTG
const VERSION = 1;
const FIXED_HEADER = 45;
const MAX_META_BYTES = 8 * 1024;

export interface NightshadePackage {
  originalName: string;
  mimeType: string;
  salt: Uint8Array;
  iv: Uint8Array;
  ciphertext: Uint8Array;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((sum, part) => sum + part.byteLength, 0);
  const output = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

function createFixedHeader(salt: Uint8Array, iv: Uint8Array, nameLength: number, mimeLength: number, ciphertextLength: number): Uint8Array {
  const buffer = new ArrayBuffer(FIXED_HEADER);
  const view = new DataView(buffer);
  const output = new Uint8Array(buffer);
  output.set(MAGIC, 0);
  view.setUint8(4, VERSION);
  output.set(salt, 5);
  output.set(iv, 21);
  view.setUint16(33, nameLength, false);
  view.setUint16(35, mimeLength, false);
  view.setBigUint64(37, BigInt(ciphertextLength), false);
  return output;
}

function assertMagicAndVersion(bytes: Uint8Array): void {
  if (bytes.byteLength < FIXED_HEADER) throw new Error('No Nightshade payload was found.');
  for (let i = 0; i < MAGIC.length; i += 1) {
    if (bytes[i] !== MAGIC[i]) throw new Error('Invalid Nightshade header.');
  }
  if (bytes[4] !== VERSION) throw new Error(`Unsupported Nightshade format version: ${bytes[4]}.`);
}

export async function buildNightshadePackage(
  payload: Uint8Array,
  password: string,
  originalName: string,
  mimeType: string
): Promise<Uint8Array> {
  const safeName = originalName || 'recovered.bin';
  const safeMime = mimeType || 'application/octet-stream';
  const nameBytes = utf8ToBytes(safeName);
  const mimeBytes = utf8ToBytes(safeMime);
  if (nameBytes.byteLength > 0xffff || mimeBytes.byteLength > 0xffff) {
    throw new Error('Metadata is too large.');
  }

  const aad = concat(utf8ToBytes('NIGHTSHADE-STEGO'), nameBytes, mimeBytes);
  const encrypted = await encryptBytes(payload, password, aad);
  const header = createFixedHeader(
    encrypted.salt,
    encrypted.iv,
    nameBytes.byteLength,
    mimeBytes.byteLength,
    encrypted.ciphertext.byteLength
  );

  return concat(header, nameBytes, mimeBytes, encrypted.ciphertext);
}

export function parseNightshadePackage(bytes: Uint8Array): NightshadePackage {
  assertMagicAndVersion(bytes);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const nameLength = view.getUint16(33, false);
  const mimeLength = view.getUint16(35, false);
  const ciphertextLengthBig = view.getBigUint64(37, false);
  const ciphertextLength = Number(ciphertextLengthBig);
  if (!Number.isSafeInteger(ciphertextLength)) throw new Error('Nightshade payload is too large for this browser.');

  const metadataTotal = nameLength + mimeLength;
  if (metadataTotal > MAX_META_BYTES) throw new Error('Nightshade metadata exceeds safety limits.');

  const payloadOffset = FIXED_HEADER + metadataTotal;
  const expectedLength = payloadOffset + ciphertextLength;
  if (expectedLength !== bytes.byteLength) throw new Error('Nightshade payload is truncated or corrupted.');

  const salt = bytes.slice(5, 21);
  const iv = bytes.slice(21, 33);
  const nameBytes = bytes.slice(FIXED_HEADER, FIXED_HEADER + nameLength);
  const mimeStart = FIXED_HEADER + nameLength;
  const mimeBytes = bytes.slice(mimeStart, mimeStart + mimeLength);
  const ciphertext = bytes.slice(payloadOffset);

  return {
    originalName: bytesToUtf8(nameBytes),
    mimeType: bytesToUtf8(mimeBytes),
    salt,
    iv,
    ciphertext,
  };
}

export async function decryptNightshadePackage(bytes: Uint8Array, password: string): Promise<{ data: Uint8Array; name: string; mime: string }> {
  const parsed = parseNightshadePackage(bytes);
  const aad = concat(utf8ToBytes('NIGHTSHADE-STEGO'), utf8ToBytes(parsed.originalName), utf8ToBytes(parsed.mimeType));
  const data = await decryptBytes(parsed.ciphertext, password, parsed.salt, parsed.iv, aad);
  return { data, name: parsed.originalName, mime: parsed.mimeType };
}

export function isNightshadePackage(bytes: Uint8Array): boolean {
  if (bytes.byteLength < 5) return false;
  return bytes[0] === MAGIC[0] && bytes[1] === MAGIC[1] && bytes[2] === MAGIC[2] && bytes[3] === MAGIC[3] && bytes[4] === VERSION;
}

export const NIGHTSHADE_FOOTER_BYTES = 12;
export const NIGHTSHADE_MAGIC = MAGIC;
export const NIGHTSHADE_FIXED_HEADER = FIXED_HEADER;
