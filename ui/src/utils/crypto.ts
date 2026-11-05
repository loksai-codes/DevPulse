/**
 * Web Crypto SHA-256 utilities with bulletproof fallback
 * Works across secure contexts, non-secure contexts, Node, and WebViews.
 */

export const GENESIS_HASH = '0'.repeat(64);

// Pure JS SHA-256 fallback implementation
function sha256Fallback(ascii: string): string {
  function rightRotate(value: number, amount: number) {
    return (value >>> amount) | (value << (32 - amount));
  }

  const mathPow = Math.pow;
  const maxWord = mathPow(2, 32);
  let lengthProperty = 'length';
  let i = 0, j = 0;
  let result = '';

  const words: number[] = [];
  const asciiBitLength = ascii[lengthProperty as unknown as number] as unknown as number * 8;

  const hash: number[] = [];
  const k: number[] = [];
  let primeCounter = 0;

  const isComposite: Record<number, boolean> = {};
  for (let candidate = 2; primeCounter < 64; candidate++) {
    if (!isComposite[candidate]) {
      for (let composite = candidate * candidate; composite < 312; composite += candidate) {
        isComposite[composite] = true;
      }
      hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
      k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
    }
  }

  ascii += '\x80';
  while ((ascii[lengthProperty as unknown as number] as unknown as number % 64) - 56) ascii += '\x00';
  for (i = 0; i < (ascii[lengthProperty as unknown as number] as unknown as number); i++) {
    j = ascii.charCodeAt(i);
    words[i >> 2] = (words[i >> 2] || 0) | (j << ((3 - (i % 4)) * 8));
  }
  words[words[lengthProperty as unknown as number] as unknown as number] = (asciiBitLength / maxWord) | 0;
  words[words[lengthProperty as unknown as number] as unknown as number] = asciiBitLength | 0;

  for (j = 0; j < (words[lengthProperty as unknown as number] as unknown as number);) {
    const w = words.slice(j, (j += 16));
    const oldHash = hash.slice(0);

    for (i = 0; i < 64; i++) {
      const w15 = w[i - 15] || 0;
      const w2 = w[i - 2] || 0;

      const s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
      const s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
      w[i] = i < 16 ? (w[i] || 0) : (((w[i - 16] || 0) + s0 + (w[i - 7] || 0) + s1) | 0);

      const h0 = hash[0] || 0, h1 = hash[1] || 0, h2 = hash[2] || 0, h3 = hash[3] || 0;
      const h4 = hash[4] || 0, h5 = hash[5] || 0, h6 = hash[6] || 0, h7 = hash[7] || 0;

      const S1 = rightRotate(h4, 6) ^ rightRotate(h4, 11) ^ rightRotate(h4, 25);
      const ch = (h4 & h5) ^ (~h4 & h6);
      const temp1 = (h7 + S1 + ch + (k[i] || 0) + (w[i] || 0)) | 0;
      const S0 = rightRotate(h0, 2) ^ rightRotate(h0, 13) ^ rightRotate(h0, 22);
      const maj = (h0 & h1) ^ (h0 & h2) ^ (h1 & h2);
      const temp2 = (S0 + maj) | 0;

      hash[7] = hash[6] || 0;
      hash[6] = hash[5] || 0;
      hash[5] = hash[4] || 0;
      hash[4] = ((h3 + temp1) | 0);
      hash[3] = hash[2] || 0;
      hash[2] = hash[1] || 0;
      hash[1] = hash[0] || 0;
      hash[0] = ((temp1 + temp2) | 0);
    }

    for (i = 0; i < 8; i++) {
      hash[i] = ((hash[i] || 0) + (oldHash[i] || 0)) | 0;
    }
  }

  for (i = 0; i < 8; i++) {
    for (let b = 3; b >= 0; b--) {
      const byte = ((hash[i] || 0) >> (b * 8)) & 255;
      result += (byte < 16 ? '0' : '') + byte.toString(16);
    }
  }
  return result;
}

export async function sha256(text: string): Promise<string> {
  try {
    if (typeof window !== 'undefined' && window.crypto && window.crypto.subtle && window.crypto.subtle.digest) {
      const encoder = new TextEncoder();
      const data = encoder.encode(text);
      const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
    }
  } catch {
    // SubtleCrypto failed or unavailable, use pure JS fallback
  }

  return sha256Fallback(text);
}

/**
 * Computes canonical audit entry hash over prevHash+seq+event+detail
 */
export async function computeAuditHash(
  prevHash: string,
  seq: number,
  event: string,
  detail: Record<string, unknown> | string
): Promise<string> {
  const detailStr = typeof detail === 'string' ? detail : JSON.stringify(detail);
  const canonical = `${prevHash}|${seq}|${event}|${detailStr}`;
  return sha256(canonical);
}

/**
 * Computes deterministic diff hash matching DevPulse length-prefixed format
 */
export async function computeDiffHash(rawDiff: string): Promise<string> {
  const normalized = rawDiff.replace(/\r\n/g, '\n').trim();
  const payload = `raw:${normalized.length}:${normalized}`;
  return sha256(payload);
}
