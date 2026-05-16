const BYTES_PER_MB = 1024 * 1024;

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < BYTES_PER_MB) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / BYTES_PER_MB).toFixed(1)} MB`;
}

export function parseMbToBytes(input: string): number | null {
  const trimmed = input.trim();
  if (!trimmed) return null;
  const value = parseFloat(trimmed);
  if (Number.isNaN(value)) return null;
  return Math.round(value * BYTES_PER_MB);
}

export function bytesToMb(bytes: number): string {
  return (bytes / BYTES_PER_MB).toString();
}

export function parseOptionalInt(input: string): number | null {
  const trimmed = input.trim();
  if (!trimmed) return null;
  const value = parseInt(trimmed, 10);
  if (Number.isNaN(value)) return null;
  return value;
}
