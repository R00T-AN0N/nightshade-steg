import { NIGHTSHADE_FIXED_HEADER, NIGHTSHADE_MAGIC, NIGHTSHADE_FOOTER_BYTES, buildNightshadePackage, decryptNightshadePackage, isNightshadePackage, parseNightshadePackage } from './container.js';

function loadImage(file: File): Promise<ImageBitmap> {
  if (!('createImageBitmap' in window)) return Promise.reject(new Error('Image decoding is not supported in this browser.'));
  return createImageBitmap(file);
}

export interface ImageInfo {
  width: number;
  height: number;
  channels: number;
  capacityBytes: number;
}

export interface SteganalysisMetrics {
  sampleBits: number;
  lsbEntropy: number;
  chiSquare: number;
  chiSquareP: number;
  neighborCorrelation: number;
  transitionRate: number;
  rsRegular: number;
  rsSingular: number;
  rsImbalance: number;
  signals: string[];
}

export interface PayloadAnalysis {
  verdict: 'confirmed' | 'possible' | 'not_detected';
  title: string;
  detail: string;
  method: string;
  score: number;
  metrics?: SteganalysisMetrics;
  metadata?: {
    name: string;
    mime: string;
    packageBytes: number;
    estimatedDataBytes: number;
  };
}

export async function getImageInfo(file: File): Promise<ImageInfo> {
  const bitmap = await loadImage(file);
  const width = bitmap.width;
  const height = bitmap.height;
  bitmap.close();
  const channels = width * height * 3;
  return { width, height, channels, capacityBytes: Math.floor(channels / 8) };
}

function extractBits(data: Uint8ClampedArray, countBytes: number): Uint8Array {
  const out = new Uint8Array(countBytes);
  let outIndex = 0;
  let bitIndex = 0;
  for (let i = 0; i < data.length && outIndex < countBytes; i += 4) {
    for (let channel = 0; channel < 3 && outIndex < countBytes; channel += 1) {
      const bit = data[i + channel] & 1;
      out[outIndex] |= bit << bitIndex;
      bitIndex += 1;
      if (bitIndex === 8) {
        bitIndex = 0;
        outIndex += 1;
      }
    }
  }
  return out;
}

function writeBits(data: Uint8ClampedArray, payload: Uint8Array): void {
  let payloadByte = 0;
  let payloadBit = 0;
  for (let i = 0; i < data.length && payloadByte < payload.length; i += 4) {
    for (let channel = 0; channel < 3 && payloadByte < payload.length; channel += 1) {
      const bit = (payload[payloadByte] >> payloadBit) & 1;
      data[i + channel] = (data[i + channel] & 0xfe) | bit;
      payloadBit += 1;
      if (payloadBit === 8) {
        payloadBit = 0;
        payloadByte += 1;
      }
    }
  }
  if (payloadByte !== payload.length) throw new Error('Carrier capacity was exhausted while writing the payload.');
}

function readPackageLengthFromFooter(bytes: Uint8Array): number {
  if (bytes.byteLength < NIGHTSHADE_FOOTER_BYTES) throw new Error('No Nightshade footer was found.');
  const footerStart = bytes.byteLength - NIGHTSHADE_FOOTER_BYTES;
  for (let i = 0; i < 4; i += 1) {
    if (bytes[footerStart + 8 + i] !== NIGHTSHADE_MAGIC[i]) throw new Error('No Nightshade payload was found in this file.');
  }
  const view = new DataView(bytes.buffer, bytes.byteOffset + footerStart, NIGHTSHADE_FOOTER_BYTES);
  const length = Number(view.getBigUint64(0, false));
  if (!Number.isSafeInteger(length) || length <= 0 || length > bytes.byteLength - NIGHTSHADE_FOOTER_BYTES) {
    throw new Error('Nightshade footer is invalid.');
  }
  return length;
}

function createPackageAnalysis(packageBytes: Uint8Array, method: string): PayloadAnalysis {
  const parsed = parseNightshadePackage(packageBytes);
  const estimatedDataBytes = Math.max(0, parsed.ciphertext.byteLength - 16);
  return {
    verdict: 'confirmed',
    title: 'Nightshade payload detected',
    detail: 'Payload metadata was recovered without a password. The encrypted data still requires the password to open.',
    method,
    score: 100,
    metadata: {
      name: parsed.originalName || 'unknown file',
      mime: parsed.mimeType || 'application/octet-stream',
      packageBytes: packageBytes.byteLength,
      estimatedDataBytes,
    },
  };
}

function findAscii(bytes: Uint8Array, value: string): boolean {
  const needle = new TextEncoder().encode(value.toLowerCase());
  for (let start = 0; start <= bytes.length - needle.length; start += 1) {
    let found = true;
    for (let index = 0; index < needle.length; index += 1) {
      const byte = bytes[start + index];
      const lower = byte >= 65 && byte <= 90 ? byte + 32 : byte;
      if (lower !== needle[index]) { found = false; break; }
    }
    if (found) return true;
  }
  return false;
}

function formatByteCount(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function genericFileHint(file: File, bytes: Uint8Array): PayloadAnalysis {
  const lowerName = file.name.toLowerCase();
  const isJpeg = file.type === 'image/jpeg' || /\.jpe?g$/.test(lowerName);
  const isPng = file.type === 'image/png' || /\.png$/.test(lowerName);
  const isGif = file.type === 'image/gif' || /\.gif$/.test(lowerName);
  const isPdf = file.type === 'application/pdf' || /\.pdf$/.test(lowerName);
  let contentEnd = -1;
  if (isJpeg) {
    for (let index = bytes.length - 2; index >= 0; index -= 1) {
      if (bytes[index] === 0xff && bytes[index + 1] === 0xd9) { contentEnd = index + 2; break; }
    }
  } else if (isPng) {
    const marker = new Uint8Array([0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82]);
    for (let index = 0; index <= bytes.length - marker.length; index += 1) {
      if (marker.every((byte, offset) => bytes[index + offset] === byte)) { contentEnd = index + marker.length; break; }
    }
  } else if (isGif) {
    contentEnd = bytes.lastIndexOf(0x3b) + 1;
  } else if (isPdf) {
    const eof = new TextDecoder().decode(bytes).lastIndexOf('%%EOF');
    if (eof >= 0) contentEnd = eof + 5;
  }
  if (contentEnd > 0 && bytes.length - contentEnd >= 16) {
    return {
      verdict: 'possible',
      title: 'Possible embedded data',
      detail: `${formatByteCount(bytes.length - contentEnd)} of trailing data was found after the normal ${file.type || 'file'} end marker. This may be a steganography payload or ordinary appended data.`,
      method: 'Cross-tool trailing-data inspection',
      score: 62,
    };
  }
  if (findAscii(bytes, 'steghide') || findAscii(bytes, 'openstego') || findAscii(bytes, 'outguess') || findAscii(bytes, 'payload')) {
    return {
      verdict: 'possible',
      title: 'Possible steganography marker',
      detail: 'A known steganography-related marker was found, but this file is not a Nightshade package and cannot be decoded by this app.',
      method: 'Cross-tool marker scan',
      score: 45,
    };
  }
  return {
    verdict: 'not_detected',
    title: 'No known payload detected',
    detail: 'No Nightshade marker, known tool marker, or obvious appended data was found. Hidden data may still exist using another method.',
    method: 'Cross-tool structure and marker scan',
    score: 0,
  };
}

function erfcApprox(value: number): number {
  // Abramowitz-Stegun style approximation; enough precision for a UI heuristic.
  const sign = value < 0 ? -1 : 1;
  const x = Math.abs(value);
  const t = 1 / (1 + 0.3275911 * x);
  const polynomial = (((((1.061405429 * t - 1.453152027) * t) + 1.421413741) * t - 0.284496736) * t + 0.254829592) * t;
  const erf = 1 - polynomial * Math.exp(-x * x);
  return sign < 0 ? 2 - (1 + erf) : 1 - erf;
}

function chiSquarePValue(chiSquare: number): number {
  return Math.max(0, Math.min(1, erfcApprox(Math.sqrt(Math.max(0, chiSquare) / 2))));
}

function buildSteganalysisMetrics(imageData: ImageData, capacity: number): SteganalysisMetrics {
  // Limit work on very large images while keeping a deterministic spread over RGB bytes.
  const maxChannels = Math.min(imageData.width * imageData.height * 3, 300_000);
  const stride = Math.max(1, Math.floor((imageData.width * imageData.height * 3) / maxChannels));

  let ones = 0;
  let zeros = 0;
  let transitions = 0;
  let pairs = 0;
  let previousBit = -1;

  // LSB pair counts are the basis of the chi-square signal.
  let even = 0;
  let odd = 0;

  // RS-style groups: four neighboring RGB samples at a time.
  let regular = 0;
  let singular = 0;
  let groups = 0;

  const values: number[] = [];
  for (let channelIndex = 0, sampleIndex = 0; channelIndex < imageData.data.length && sampleIndex < maxChannels; channelIndex += 1) {
    // Skip alpha channels and sample deterministically.
    if (channelIndex % 4 === 3) continue;
    if (channelIndex % stride !== 0) continue;

    const value = imageData.data[channelIndex];
    const bit = value & 1;
    values.push(value);

    if (bit) ones += 1; else zeros += 1;
    if (previousBit >= 0) {
      pairs += 1;
      if (bit !== previousBit) transitions += 1;
    }
    previousBit = bit;
    if (value & 1) odd += 1; else even += 1;
    sampleIndex += 1;
  }

  const total = ones + zeros;
  const p1 = total ? ones / total : 0.5;
  const p0 = total ? zeros / total : 0.5;
  const entropy = total
    ? -(p0 * Math.log2(Math.max(p0, Number.EPSILON)) + p1 * Math.log2(Math.max(p1, Number.EPSILON)))
    : 0;

  const expected = total / 2;
  const chiSquare = expected > 0
    ? ((even - expected) ** 2 + (odd - expected) ** 2) / expected
    : 0;
  const chiSquareP = chiSquarePValue(chiSquare);

  const transitionRate = pairs ? transitions / pairs : 0.5;
  // Correlation of adjacent LSBs, centered around zero.
  const mean = total ? (ones / total) : 0.5;
  let covariance = 0;
  let variance = 0;
  let previous = -1;
  for (let i = 0; i < values.length; i += 1) {
    const bit = values[i] & 1;
    variance += (bit - mean) ** 2;
    if (previous >= 0) covariance += (previous - mean) * (bit - mean);
    previous = bit;
  }
  const neighborCorrelation = variance > 0 && values.length > 1
    ? Math.max(-1, Math.min(1, covariance / variance))
    : 0;

  const discrimination = (group: number[], mask: number[]): number => {
    let sum = 0;
    for (let i = 0; i < group.length - 1; i += 1) {
      sum += Math.abs(group[i] - group[i + 1]);
    }
    return sum;
  };
  const flip = (value: number): number => (value & 1) ? value - 1 : value + 1;
  for (let i = 0; i + 3 < values.length; i += 4) {
    const group = values.slice(i, i + 4);
    const flipped = group.map((value, index) => (index % 2 === 0 ? flip(value) : value));
    const d0 = discrimination(group, [1, 0, 1, 0]);
    const d1 = discrimination(flipped, [1, 0, 1, 0]);
    if (d1 > d0) regular += 1;
    else if (d1 < d0) singular += 1;
    groups += 1;
  }

  const rsImbalance = groups ? Math.abs(regular - singular) / groups : 0;

  const signals: string[] = [];
  if (entropy >= 0.995) signals.push('near-maximum LSB entropy');
  if (chiSquareP >= 0.95) signals.push('even/odd LSB balance');
  if (Math.abs(neighborCorrelation) < 0.04 && total >= 20_000) signals.push('weak LSB neighbor correlation');
  if (rsImbalance < 0.03 && groups >= 1_000) signals.push('low RS regular/singular separation');

  return {
    sampleBits: total,
    lsbEntropy: entropy,
    chiSquare,
    chiSquareP,
    neighborCorrelation,
    transitionRate,
    rsRegular: groups ? regular / groups : 0,
    rsSingular: groups ? singular / groups : 0,
    rsImbalance,
    signals,
  };
}

function steganalysisScore(metrics: SteganalysisMetrics): number {
  if (metrics.sampleBits < 20_000) return 0;

  // These are intentionally bounded heuristic contributions, not calibrated probabilities.
  const entropySignal = Math.max(0, Math.min(1, (metrics.lsbEntropy - 0.985) / 0.015));
  const chiSignal = metrics.chiSquareP >= 0.95 ? Math.min(1, (metrics.chiSquareP - 0.95) / 0.05) : 0;
  const correlationSignal = Math.max(0, Math.min(1, (0.04 - Math.abs(metrics.neighborCorrelation)) / 0.04));
  const rsSignal = Math.max(0, Math.min(1, (0.03 - metrics.rsImbalance) / 0.03));

  return Math.round((entropySignal * 0.30 + chiSignal * 0.30 + correlationSignal * 0.20 + rsSignal * 0.20) * 100);
}

function analyzeImageBits(imageData: ImageData, capacity: number): PayloadAnalysis {
  const metrics = buildSteganalysisMetrics(imageData, capacity);
  const score = steganalysisScore(metrics);
  const signalText = metrics.signals.length
    ? `Signals: ${metrics.signals.join(', ')}.`
    : 'No strong statistical signal crossed the local heuristic thresholds.';

  if (score >= 65) {
    return {
      verdict: 'possible',
      title: 'Steganalysis signal detected',
      detail: `${signalText} Multiple LSB statistics resemble patterns that can occur after LSB embedding, but natural images can produce similar measurements.`,
      method: 'LSB entropy + chi-square + neighbor correlation + RS-style analysis',
      score,
      metrics,
    };
  }

  return {
    verdict: 'not_detected',
    title: 'No strong steganalysis signal',
    detail: `${signalText} This does not rule out steganography, especially methods that do not alter pixel LSBs.`,
    method: 'LSB entropy + chi-square + neighbor correlation + RS-style analysis',
    score,
    metrics,
  };
}

export async function analyzeCarrier(file: File): Promise<PayloadAnalysis> {
  if (!isImageFile(file)) {
    const bytes = new Uint8Array(await file.arrayBuffer());
    try {
      const length = readPackageLengthFromFooter(bytes);
      const packageStart = bytes.byteLength - NIGHTSHADE_FOOTER_BYTES - length;
      return createPackageAnalysis(bytes.slice(packageStart, packageStart + length), 'Nightshade binary footer');
    } catch {
      return genericFileHint(file, bytes);
    }
  }

  const bitmap = await loadImage(file);
  const canvas = document.createElement('canvas');
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  if (!ctx) throw new Error('Canvas 2D is unavailable.');
  ctx.drawImage(bitmap, 0, 0);
  bitmap.close();
  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const capacity = Math.floor((canvas.width * canvas.height * 3) / 8);
  const header = extractBits(imageData.data, Math.min(capacity, NIGHTSHADE_FIXED_HEADER));
  if (isNightshadePackage(header)) {
    const headerView = new DataView(header.buffer, header.byteOffset, header.byteLength);
    const nameLength = headerView.getUint16(33, false);
    const mimeLength = headerView.getUint16(35, false);
    const ciphertextLength = Number(headerView.getBigUint64(37, false));
    const totalLength = NIGHTSHADE_FIXED_HEADER + nameLength + mimeLength + ciphertextLength;
    if (!Number.isSafeInteger(totalLength) || totalLength > capacity) throw new Error('Nightshade payload metadata is invalid or truncated.');
    return createPackageAnalysis(extractBits(imageData.data, totalLength), 'Nightshade image LSB marker');
  }
  if (!isImageFile(file)) return genericFileHint(file, new Uint8Array(await file.arrayBuffer()));
  return analyzeImageBits(imageData, capacity);
}

function isImageFile(file: File): boolean {
  return file.type === 'image/png' || file.type === 'image/bmp' || /\.(png|bmp)$/i.test(file.name);
}

export async function encodeImageCarrier(
  carrier: File,
  payload: Uint8Array,
  password: string,
  originalName: string,
  mimeType: string
): Promise<{ blob: Blob; info: ImageInfo; packageBytes: number }> {
  const bitmap = await loadImage(carrier);
  const canvas = document.createElement('canvas');
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  if (!ctx) throw new Error('Canvas 2D is unavailable.');
  ctx.drawImage(bitmap, 0, 0);
  bitmap.close();

  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const packageBytes = await buildNightshadePackage(payload, password, originalName, mimeType);
  const info: ImageInfo = {
    width: canvas.width,
    height: canvas.height,
    channels: canvas.width * canvas.height * 3,
    capacityBytes: Math.floor((canvas.width * canvas.height * 3) / 8),
  };
  if (packageBytes.byteLength > info.capacityBytes) {
    throw new Error(`Carrier is too small. Need ${packageBytes.byteLength.toLocaleString()} bytes, capacity is ${info.capacityBytes.toLocaleString()} bytes.`);
  }

  writeBits(imageData.data, packageBytes);
  ctx.putImageData(imageData, 0, 0);
  const blob = await new Promise<Blob>((resolve, reject) => {
    canvas.toBlob((result) => result ? resolve(result) : reject(new Error('Unable to encode the output PNG.')), 'image/png');
  });
  return { blob, info, packageBytes: packageBytes.byteLength };
}

export async function decodeImageCarrier(file: File, password: string): Promise<{ data: Uint8Array; name: string; mime: string; imageInfo: ImageInfo }> {
  const bitmap = await loadImage(file);
  const canvas = document.createElement('canvas');
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  if (!ctx) throw new Error('Canvas 2D is unavailable.');
  ctx.drawImage(bitmap, 0, 0);
  bitmap.close();

  const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
  const capacity = Math.floor((canvas.width * canvas.height * 3) / 8);
  const first = extractBits(imageData.data, Math.min(capacity, NIGHTSHADE_FIXED_HEADER));
  if (!isNightshadePackage(first)) throw new Error('This image does not contain a Nightshade payload.');

  const headerView = new DataView(first.buffer, first.byteOffset, first.byteLength);
  const nameLength = headerView.getUint16(33, false);
  const mimeLength = headerView.getUint16(35, false);
  const ciphertextLength = Number(headerView.getBigUint64(37, false));
  const totalLength = NIGHTSHADE_FIXED_HEADER + nameLength + mimeLength + ciphertextLength;
  if (!Number.isSafeInteger(totalLength) || totalLength > capacity) throw new Error('Nightshade payload length exceeds the carrier capacity.');

  const packageBytes = extractBits(imageData.data, totalLength);
  const recovered = await decryptNightshadePackage(packageBytes, password);
  return {
    ...recovered,
    imageInfo: {
      width: canvas.width,
      height: canvas.height,
      channels: canvas.width * canvas.height * 3,
      capacityBytes: capacity,
    },
  };
}

export async function encodeBinaryAppendCarrier(
  carrier: File,
  payload: Uint8Array,
  password: string,
  originalName: string,
  mimeType: string
): Promise<{ blob: Blob; packageBytes: number }> {
  const packageBytes = await buildNightshadePackage(payload, password, originalName, mimeType);
  const footer = new ArrayBuffer(NIGHTSHADE_FOOTER_BYTES);
  const footerView = new DataView(footer);
  footerView.setBigUint64(0, BigInt(packageBytes.byteLength), false);
  new Uint8Array(footer, 8).set(NIGHTSHADE_MAGIC);
  return {
    blob: new Blob([carrier, new Uint8Array(packageBytes), new Uint8Array(footer)], { type: carrier.type || 'application/octet-stream' }),
    packageBytes: packageBytes.byteLength,
  };
}

export async function decodeBinaryAppendCarrier(file: File, password: string): Promise<{ data: Uint8Array; name: string; mime: string; packageBytes: number }> {
  const carrierBytes = new Uint8Array(await file.arrayBuffer());
  const length = readPackageLengthFromFooter(carrierBytes);
  const packageStart = carrierBytes.byteLength - NIGHTSHADE_FOOTER_BYTES - length;
  const packageBytes = carrierBytes.slice(packageStart, carrierBytes.byteLength - NIGHTSHADE_FOOTER_BYTES);
  const recovered = await decryptNightshadePackage(packageBytes, password);
  return { ...recovered, packageBytes: length };
}
