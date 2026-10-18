"use strict";
/* ---------------- big-integer helpers ---------------- */
const mod = (a, p) => { const r = a % p; return r >= 0n ? r : r + p; };
function inv(a, p) {
  let r0 = mod(a, p), r1 = p, s0 = 1n, s1 = 0n;
  while (r1 !== 0n) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
  return mod(s0, p);
}

/* ---------------- curves: y^2 = x^3 + 7 ---------------- */
const CURVES = {
  secp256k1: {
    id: "secp256k1", label: "secp256k1 (real parameters)",
    p: 2n ** 256n - 2n ** 32n - 977n, b: 7n,
    Gx: 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n,
    Gy: 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n,
    n: 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n, bytes: 32
  },
  toy17: { id: "toy17", label: "Toy curve over F17 (as in Part 1)", p: 17n, b: 7n, Gx: 1n, Gy: 5n, n: 0n, bytes: 1 }
};

// null is the point at infinity
function ecAdd(c, P, Q) {
  if (!P) return Q;
  if (!Q) return P;
  const p = c.p;
  let m;
  if (P[0] === Q[0]) {
    if ((P[1] + Q[1]) % p === 0n) return null;
    m = mod(3n * P[0] * P[0] * inv(2n * P[1], p), p);
  } else {
    m = mod((Q[1] - P[1]) * inv(Q[0] - P[0], p), p);
  }
  const x3 = mod(m * m - P[0] - Q[0], p);
  const y3 = mod(m * (P[0] - x3) - P[1], p);
  return [x3, y3];
}
const ecNeg = (c, P) => P ? [P[0], mod(-P[1], c.p)] : null;
function ecMul(c, k, P) {
  let R = null, A = P;
  while (k > 0n) {
    if (k & 1n) R = ecAdd(c, R, A);
    A = ecAdd(c, A, A);
    k >>= 1n;
  }
  return R;
}
const ecEq = (P, Q) => (!P && !Q) || (P && Q && P[0] === Q[0] && P[1] === Q[1]);
const onCurve = (c, P) => !P || mod(P[1] * P[1] - (P[0] ** 3n + c.b), c.p) === 0n;
const genOf = c => [c.Gx, c.Gy];

// order of the toy curve generator (small group)
(function () {
  const c = CURVES.toy17, G = genOf(c);
  let P = G, n = 1n;
  while (P) { P = ecAdd(c, P, G); n++; }
  c.n = n;
})();

// restricted private-key range [1, keyRange]
function keyRange(c, bits) {
  const full = 1n << BigInt(bits), max = c.n - 1n;
  return full < max ? full : max;
}
function randBelow(max) { // uniform-ish in [1, max]
  const nb = Math.ceil(max.toString(2).length / 8) + 8;
  const a = new Uint8Array(nb);
  crypto.getRandomValues(a);
  let v = 0n;
  for (const x of a) v = (v << 8n) | BigInt(x);
  return v % max + 1n;
}

/* ---------------- bytes, hex, SHA-256 ---------------- */
const textEnc = new TextEncoder(), textDec = new TextDecoder();
const toHex = b => Array.from(b, x => x.toString(16).padStart(2, "0")).join("");
function fromHex(h) {
  h = h.replace(/[^0-9a-fA-F]/g, "");
  if (h.length % 2) h = "0" + h;
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(2 * i, 2), 16);
  return out;
}
function bigToBytes(x, len) {
  const out = new Uint8Array(len);
  for (let i = len - 1; i >= 0; i--) { out[i] = Number(x & 255n); x >>= 8n; }
  return out;
}
function concat(...arrs) {
  const out = new Uint8Array(arrs.reduce((s, a) => s + a.length, 0));
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
}
const K256 = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
function sha256(msg) {
  const H = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]);
  const l = msg.length, padLen = ((l + 9 + 63) >> 6) << 6;
  const buf = new Uint8Array(padLen);
  buf.set(msg); buf[l] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(padLen - 8, Math.floor(l / 0x20000000), false);
  dv.setUint32(padLen - 4, (l << 3) >>> 0, false);
  const w = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < padLen; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + 4 * i, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + K256[i] + w[i]) | 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const mj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + mj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
    H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
  }
  const out = new Uint8Array(32), odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setUint32(4 * i, H[i], false);
  return out;
}

/* ---------------- the toy ECC encryption scheme ---------------- */
function keystream(c, S, len) {
  const sx = S ? bigToBytes(S[0], c.bytes) : textEnc.encode("infinity");
  const pre = textEnc.encode("ECTOY");
  const out = new Uint8Array(len);
  let off = 0, ctr = 0;
  while (off < len) {
    const blk = sha256(concat(pre, sx, new Uint8Array([ctr >>> 24, ctr >>> 16 & 255, ctr >>> 8 & 255, ctr & 255])));
    out.set(blk.subarray(0, Math.min(32, len - off)), off);
    off += 32; ctr++;
  }
  return out;
}
const xorBytes = (a, b) => a.map((v, i) => v ^ b[i]);
function eccEncrypt(c, Q, msg, r) {
  const R = ecMul(c, r, genOf(c));
  const S = ecMul(c, r, Q);
  const ks = keystream(c, S, msg.length);
  return { r, R, S, ks, ct: xorBytes(msg, ks) };
}
function eccDecrypt(c, d, R, ct) {
  const S = ecMul(c, d, R);
  return xorBytes(ct, keystream(c, S, ct.length));
}
function decryptWithSecret(c, S, ct) { return xorBytes(ct, keystream(c, S, ct.length)); }

/* ---------------- attacks on the restricted key space ---------------- */
const tick = () => new Promise(r => setTimeout(r, 0));

// exhaustive search for k in [1, maxK] with kG = T, Jacobian coordinates (no inversion in the loop)
async function bruteForceAttack(c, T, maxK, onProg, cancelled) {
  const p = c.p, Gx = c.Gx, Gy = c.Gy, t0 = performance.now();
  let X = Gx, Y = Gy, Z = 1n;
  const total = Number(maxK), CH = 1500;
  for (let i = 1; i <= total; i++) {
    const Z2 = Z * Z % p;
    if (X === T[0] * Z2 % p && Y === T[1] * Z2 % p * Z % p)
      return { k: BigInt(i), steps: i, ms: performance.now() - t0 };
    // acc = acc + G  (mixed addition)
    const U2 = Gx * Z2 % p, S2 = Gy * Z % p * Z2 % p;
    let H = U2 - X; if (H < 0n) H += p;
    let rr = S2 - Y; if (rr < 0n) rr += p;
    if (H === 0n) {
      if (rr !== 0n) break; // reached infinity: the cycle is over
      const A = X * X % p, B = Y * Y % p, C = B * B % p, t = X + B;
      const D = 2n * mod(t * t - A - C, p) % p, E = 3n * A % p, F = E * E % p;
      const X3 = mod(F - 2n * D, p), Y3 = mod(E * (D - X3) - 8n * C, p), Z3 = 2n * Y * Z % p;
      X = X3; Y = Y3; Z = Z3;
    } else {
      const HH = H * H % p, HHH = H * HH % p, V = X * HH % p;
      const X3 = mod(rr * rr - HHH - 2n * V, p);
      const Y3 = mod(rr * (V - X3) - Y * HHH, p);
      Z = Z * H % p; X = X3; Y = Y3;
    }
    if (i % CH === 0) {
      if (onProg) onProg(i / total);
      await tick();
      if (cancelled && cancelled()) return { k: null, steps: i, ms: performance.now() - t0, cancelled: true };
    }
  }
  return { k: null, steps: total, ms: performance.now() - t0 };
}

// baby-step giant-step for k in [1, maxK]
async function bsgsAttack(c, T, maxK, onProg, cancelled) {
  const t0 = performance.now(), G = genOf(c);
  const m = Math.max(1, Math.ceil(Math.sqrt(Number(maxK))));
  const table = new Map();
  let P = null, steps = 0;
  for (let j = 1; j <= m; j++) {
    P = ecAdd(c, P, G); steps++;
    if (P) table.set(P[0], j);
    if (j % 400 === 0) {
      if (onProg) onProg(0.5 * j / m);
      await tick();
      if (cancelled && cancelled()) return { k: null, steps, ms: performance.now() - t0, cancelled: true, table: table.size };
    }
  }
  const step = ecNeg(c, P); // -mG
  let cand = T;
  for (let i = 0; i <= m + 1; i++) {
    if (cand) {
      const j = table.get(cand[0]);
      if (j !== undefined) {
        const k = BigInt(i) * BigInt(m) + BigInt(j);
        if (ecEq(ecMul(c, k, G), T)) return { k, steps, ms: performance.now() - t0, table: table.size };
      }
    }
    cand = ecAdd(c, cand, step); steps++;
    if (i % 400 === 0) {
      if (onProg) onProg(0.5 + 0.5 * i / (m + 1));
      await tick();
      if (cancelled && cancelled()) return { k: null, steps, ms: performance.now() - t0, cancelled: true, table: table.size };
    }
  }
  return { k: null, steps, ms: performance.now() - t0, table: table.size };
}

/* ---------------- Caesar ---------------- */
const ABC = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
function caesar(text, shift) {
  const s = ((shift % 26) + 26) % 26;
  return text.replace(/[A-Za-z]/g, ch => {
    const b = ch < "a" ? 65 : 97;
    return String.fromCharCode((ch.charCodeAt(0) - b + s) % 26 + b);
  });
}
function lettersOnly(s) { return s.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toUpperCase().replace(/[^A-Z]/g, ""); }
function toIdx(str) { const a = new Uint8Array(str.length); for (let i = 0; i < str.length; i++) a[i] = str.charCodeAt(i) - 65; return a; }
function idxToStr(a) { let s = ""; for (let i = 0; i < a.length; i++) s += ABC[a[i]]; return s; }

/* ---------------- language models ---------------- */
function buildModel(letterStr) {
  const L = toIdx(letterStr), n = L.length;
  const u = new Float64Array(26), b = new Float64Array(676), t = new Float64Array(17576);
  for (let i = 0; i < n; i++) {
    u[L[i]]++;
    if (i >= 1) b[L[i - 1] * 26 + L[i]]++;
    if (i >= 2) t[(L[i - 2] * 26 + L[i - 1]) * 26 + L[i]]++;
  }
  const p = new Float64Array(26), lf = new Float64Array(26), lb = new Float64Array(676), lt = new Float64Array(17576);
  for (let j = 0; j < 26; j++) { p[j] = (u[j] + 0.5) / (n + 13); lf[j] = Math.log(p[j]); }
  const kb = 0.5, kt = 0.05;
  for (let a = 0; a < 26; a++) {
    let rs = 0; for (let c = 0; c < 26; c++) rs += b[a * 26 + c];
    for (let c = 0; c < 26; c++) lb[a * 26 + c] = Math.log((b[a * 26 + c] + kb) / (rs + 26 * kb));
  }
  for (let ab = 0; ab < 676; ab++) {
    let rs = 0; for (let c = 0; c < 26; c++) rs += t[ab * 26 + c];
    for (let c = 0; c < 26; c++) lt[ab * 26 + c] = Math.log((t[ab * 26 + c] + kt) / (rs + 26 * kt));
  }
  return { n, p, lf, lb, lt };
}
function trainModel(lang, pct) {
  const all = lettersOnly(CORPUS[lang].train);
  return buildModel(all.slice(0, Math.max(50, Math.round(all.length * pct / 100))));
}

const METHODS = [
  { id: "top", name: "Most frequent letter" },
  { id: "chi", name: "Chi-squared" },
  { id: "bi", name: "Bigram log-likelihood" },
  { id: "tri", name: "Trigram log-likelihood" },
  { id: "dic", name: "Exhaustive + dictionary" }
];

// scores[method][shift]: higher = better candidate. Ciphertext c is an array of letter indices.
function scoreAll(c, model, words) {
  const n = c.length, cnt = new Array(26).fill(0);
  for (let i = 0; i < n; i++) cnt[c[i]]++;
  let mt = 0; for (let j = 1; j < 26; j++) if (model.p[j] > model.p[mt]) mt = j;
  const S = { top: [], chi: [], bi: [], tri: [], dic: [] };
  const t = new Uint8Array(n);
  for (let s = 0; s < 26; s++) {
    S.top.push(cnt[(mt + s) % 26]);
    let x = 0;
    for (let j = 0; j < 26; j++) { const e = n * model.p[j], o = cnt[(j + s) % 26]; x += (o - e) * (o - e) / e; }
    S.chi.push(-x);
    for (let i = 0; i < n; i++) t[i] = (c[i] - s + 26) % 26;
    let lb = model.lf[t[0]], lt = model.lf[t[0]];
    if (n > 1) lt += model.lb[t[0] * 26 + t[1]];
    for (let i = 1; i < n; i++) lb += model.lb[t[i - 1] * 26 + t[i]];
    for (let i = 2; i < n; i++) lt += model.lt[(t[i - 2] * 26 + t[i - 1]) * 26 + t[i]];
    S.bi.push(lb); S.tri.push(lt);
    const str = idxToStr(t);
    let d = 0;
    for (const w of words) { let pos = 0; while ((pos = str.indexOf(w, pos)) >= 0) { d += w.length * w.length; pos++; } }
    S.dic.push(d);
  }
  return S;
}
function argmaxAll(v) {
  let m = -Infinity; for (const x of v) if (x > m) m = x;
  const ties = []; v.forEach((x, i) => { if (Math.abs(x - m) < 1e-9) ties.push(i); });
  return ties;
}

/* ---------------- statistics helpers ---------------- */
function entropy(counts) {
  const n = counts.reduce((a, b) => a + b, 0); let h = 0;
  for (const c of counts) if (c) h -= c / n * Math.log2(c / n);
  return h;
}
function coincidence(counts) {
  const n = counts.reduce((a, b) => a + b, 0);
  return counts.reduce((s, c) => s + c * (c - 1), 0) / (n * (n - 1));
}
function chi2Uniform(counts) {
  const n = counts.reduce((a, b) => a + b, 0), e = n / counts.length;
  return counts.reduce((s, c) => s + (c - e) ** 2 / e, 0);
}
function popcount(v) { let c = 0; while (v) { c += v & 1; v >>= 1; } return c; }
function bitDiffRatio(a, b) { let d = 0; for (let i = 0; i < a.length; i++) d += popcount(a[i] ^ b[i]); return d / (8 * a.length); }
function onesRatio(a) { let d = 0; for (const x of a) d += popcount(x); return d / (8 * a.length); }

/* ---------------- experiments ---------------- */
function mulberry32(a) { return function () { a |= 0; a = a + 0x6D2B79F5 | 0; let t = Math.imul(a ^ a >>> 15, 1 | a); t = t + Math.imul(t ^ t >>> 7, 61 | t) ^ t; return ((t ^ t >>> 14) >>> 0) / 4294967296; }; }
function caesarExperiment(model, testLetters, words, lengths, trials, seed) {
  const rng = mulberry32(seed), T = toIdx(testLetters), res = [];
  for (const L of lengths) {
    const succ = { top: 0, chi: 0, bi: 0, tri: 0, dic: 0 };
    for (let t = 0; t < trials; t++) {
      const st = Math.floor(rng() * (T.length - L + 1)), key = 1 + Math.floor(rng() * 25);
      const c = new Uint8Array(L);
      for (let i = 0; i < L; i++) c[i] = (T[st + i] + key) % 26;
      const S = scoreAll(c, model, words);
      for (const m of METHODS) {
        const ties = argmaxAll(S[m.id]);
        if (ties.includes(key)) succ[m.id] += 1 / ties.length;
      }
    }
    const row = { L }; for (const m of METHODS) row[m.id] = 100 * succ[m.id] / trials;
    res.push(row);
  }
  return res;
}
