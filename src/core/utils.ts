export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function fileBaseName(name: string): string {
  const dot = name.lastIndexOf('.');
  return dot > 0 ? name.slice(0, dot) : name;
}

export function outputNameForImage(carrierName: string): string {
  return `${fileBaseName(carrierName)}-nightshade.png`;
}

export function outputNameForBinary(carrierName: string): string {
  return `${fileBaseName(carrierName)}-nightshade${carrierName.slice(carrierName.lastIndexOf('.')) || '.bin'}`;
}

export function isImageCarrier(file: File | null): boolean {
  if (!file) return false;
  const lower = file.name.toLowerCase();
  return file.type === 'image/png' || file.type === 'image/bmp' || lower.endsWith('.png') || lower.endsWith('.bmp');
}

export function setDownload(blob: Blob, fileName: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = fileName;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 0);
}

export function guessMode(file: File | null): 'image_lsb' | 'binary_append' {
  return isImageCarrier(file) ? 'image_lsb' : 'binary_append';
}

export function hexDump(bytes: Uint8Array, max = 256): string {
  return [...bytes.slice(0, max)].map((b) => b.toString(16).padStart(2, '0')).join(' ');
}

export function previewText(bytes: Uint8Array): string {
  const slice = bytes.slice(0, 200);
  const printable = [...slice].map((b) => b >= 32 && b <= 126 ? String.fromCharCode(b) : '.').join('');
  return printable || '(binary payload)';
}
