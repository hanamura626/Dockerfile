import { createServer, IncomingMessage, ServerResponse } from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import * as crypto from 'crypto';
import * as net from 'net';
import { promises as dnsPromises } from 'dns';
import { URL } from 'url';

// ============ Environment ============
const UUID = process.env.UUID || 'd1cf4b9c-3e57-085d-b34a-797fcf601381';
const PORT = parseInt(process.env.PORT || '3000', 10);
const SHOW_LOG = !!process.env.SHOW_LOG;
const ALLOW_ANY_UUID = ['1', 'true', 'yes'].includes(
  (process.env.ALLOW_ANY_UUID || 'true').toLowerCase(),
);

const UUID_BYTES = Buffer.from(UUID.replace(/-/g, ''), 'hex');

function log(...a: any[]) { if (SHOW_LOG) console.log(...a); }
function logErr(...a: any[]) { if (SHOW_LOG) console.error(...a); }

const BLOCKED_DOMAINS = [
  'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com',
  'speedof.me', 'testmy.net', 'bandwidth.place', 'speed.io',
  'librespeed.org', 'speedcheck.org',
];
const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;

function isBlockedDomain(host?: string | null): boolean {
  if (!host) return false;
  const h = host.toLowerCase();
  return BLOCKED_DOMAINS.some((b) => h === b || h.endsWith('.' + b));
}

// ============ Hashing / CRC / FNV ============
const md5 = (d: Buffer) => crypto.createHash('md5').update(d).digest();
const sha256 = (d: Buffer) => crypto.createHash('sha256').update(d).digest();
const hmacSha256 = (k: Buffer, d: Buffer) =>
  crypto.createHmac('sha256', k).update(d).digest();

function crc32(d: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < d.length; i++) {
    c ^= d[i];
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (c & 1 ? 0xedb88320 : 0);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function fnv1a32(d: Buffer): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < d.length; i++) {
    h ^= d[i];
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

// ============ VMess KDF ============
type HashFn = (d: Buffer) => Buffer;

function hmacWithHash(hashFn: HashFn, key: Buffer, data: Buffer): Buffer {
  let k = key;
  if (k.length > 64) k = hashFn(k);
  const kb = Buffer.alloc(64); k.copy(kb);
  const ipad = Buffer.alloc(64);
  const opad = Buffer.alloc(64);
  for (let i = 0; i < 64; i++) {
    ipad[i] = kb[i] ^ 0x36;
    opad[i] = kb[i] ^ 0x5c;
  }
  return hashFn(Buffer.concat([opad, hashFn(Buffer.concat([ipad, data]))]));
}

function vmessKdf(key: Buffer, ...paths: (string | Buffer)[]): Buffer {
  let fn: HashFn = (d) =>
    crypto.createHmac('sha256', Buffer.from('VMess AEAD KDF')).update(d).digest();
  for (const p of paths) {
    const prev = fn;
    const pb = typeof p === 'string' ? Buffer.from(p, 'utf-8') : p;
    fn = (d) => hmacWithHash(prev, pb, d);
  }
  return fn(key);
}
const vmessKdf16 = (key: Buffer, ...paths: (string | Buffer)[]) =>
  vmessKdf(key, ...paths).subarray(0, 16);
const vmessCmdKey = (u: Buffer) =>
  md5(Buffer.concat([u, Buffer.from('c48619fe-8f02-49e0-b9e9-edf763e17e21')]));

// ============ Constants ============
const SEC_AES128_GCM = 3;
const SEC_CHACHA20_POLY1305 = 4;
const SEC_NONE = 5;
const SEC_ZERO = 6;

const OPT_CHUNK_STREAM = 0x01;
const OPT_CHUNK_MASKING = 0x04;
const OPT_GLOBAL_PADDING = 0x08;
const OPT_AUTHENTICATED_LENGTH = 0x10;

const ATYP_IPV4 = 0x01, ATYP_DOMAIN = 0x02, ATYP_IPV6 = 0x03;
const CMD_TCP = 0x01, CMD_MUX = 0x03;

const KDF_AUTH_ID = 'AES Auth ID Encryption';
const KDF_HDR_LEN_KEY = 'VMess Header AEAD Key_Length';
const KDF_HDR_LEN_IV = 'VMess Header AEAD Nonce_Length';
const KDF_HDR_KEY = 'VMess Header AEAD Key';
const KDF_HDR_IV = 'VMess Header AEAD Nonce';
const KDF_RESP_LEN_KEY = 'AEAD Resp Header Len Key';
const KDF_RESP_LEN_IV = 'AEAD Resp Header Len IV';
const KDF_RESP_KEY = 'AEAD Resp Header Key';
const KDF_RESP_IV = 'AEAD Resp Header IV';
const KDF_AUTH_LEN = 'auth_len';

// ============ AEAD helpers (FIXED) ============
function chachaKey(k16: Buffer): Buffer {
  const a = md5(k16);
  return Buffer.concat([a, md5(a)]);
}
function normalizeAeadKey(sec: number, key: Buffer): Buffer {
  return sec === SEC_CHACHA20_POLY1305 ? chachaKey(key) : key.subarray(0, 16);
}

function aeadSeal(sec: number, key: Buffer, nonce: Buffer, plain: Buffer, aad?: Buffer): Buffer {
  const alg = sec === SEC_AES128_GCM ? 'aes-128-gcm' : 'chacha20-poly1305';
  const cipher = crypto.createCipheriv(
    alg,
    normalizeAeadKey(sec, key),
    nonce,
  ) as crypto.CipherGCM;
  if (aad) cipher.setAAD(aad);
  return Buffer.concat([cipher.update(plain), cipher.final(), cipher.getAuthTag()]);
}

function aeadOpen(sec: number, key: Buffer, nonce: Buffer, sealed: Buffer, aad?: Buffer): Buffer {
  const alg = sec === SEC_AES128_GCM ? 'aes-128-gcm' : 'chacha20-poly1305';
  const tag = sealed.subarray(sealed.length - 16);
  const ct = sealed.subarray(0, sealed.length - 16);
  const d = crypto.createDecipheriv(
    alg,
    normalizeAeadKey(sec, key),
    nonce,
  ) as crypto.DecipherGCM;
  if (aad) d.setAAD(aad);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

function aesEcbDecryptBlock(key: Buffer, block: Buffer): Buffer {
  const d = crypto.createDecipheriv('aes-128-ecb', key.subarray(0, 16), null);
  d.setAutoPadding(false);
  return Buffer.concat([d.update(block), d.final()]);
}

// ============ SHAKE128 XOF ============
class ShakeSizeParser {
  private buf: Buffer;
  private pos = 0;
  constructor(seed: Buffer) {
    this.buf = crypto
      .createHash('shake128', { outputLength: 131072 })
      .update(seed)
      .digest() as Buffer;
  }
  private nw(): number {
    const b = this.buf.subarray(this.pos, this.pos + 2);
    this.pos += 2;
    return (b[0] << 8) | b[1];
  }
  decodeSize(d: Buffer): number {
    return (((d[0] << 8) | d[1]) ^ this.nw()) & 0xffff;
  }
  encodeSize(s: number): Buffer {
    const v = (s ^ this.nw()) & 0xffff;
    return Buffer.from([v >> 8, v & 0xff]);
  }
  nextPaddingLen(): number { return this.nw() % 64; }
}

class NonceCounter {
  private base: Buffer;
  private count = 0;
  constructor(iv: Buffer) { this.base = iv; }
  next(size = 12): Buffer {
    const out = Buffer.from(this.base);
    out[0] = (this.count >> 8) & 0xff;
    out[1] = this.count & 0xff;
    this.count = (this.count + 1) & 0xffff;
    return out.subarray(0, size);
  }
}

// ============ VMess header parser ============
interface VmessHeader {
  command: number;
  address: string;
  port: number;
  addressType: number;
  option: number;
  security: number;
  wireSecurity: number;
  requestBodyIv: Buffer;
  requestBodyKey: Buffer;
  responseHeader: number;
  headerLength: number;
  authId: Buffer;
  responseBodyKey: Buffer;
  responseBodyIv: Buffer;
}

function parseAddress(data: Buffer, cur: number, atyp: number): [string, number] | null {
  if (atyp === ATYP_IPV4) {
    if (data.length < cur + 4) return null;
    return [Array.from(data.subarray(cur, cur + 4)).join('.'), cur + 4];
  }
  if (atyp === ATYP_DOMAIN) {
    if (data.length < cur + 1) return null;
    const L = data[cur]; cur++;
    if (!L || data.length < cur + L) return null;
    return [data.subarray(cur, cur + L).toString('utf-8'), cur + L];
  }
  if (atyp === ATYP_IPV6) {
    if (data.length < cur + 16) return null;
    const parts: string[] = [];
    for (let j = 0; j < 16; j += 2) parts.push(data.readUInt16BE(cur + j).toString(16));
    return [parts.join(':'), cur + 16];
  }
  throw new Error(`invalid atyp ${atyp}`);
}

function tryParseVmessHeader(
  data: Buffer,
  uuidBytes: Buffer,
  nowSec = Math.floor(Date.now() / 1000),
): VmessHeader | null {
  if (data.length < 16) return null;
  const cmdKey = vmessCmdKey(uuidBytes);
  const authId = data.subarray(0, 16);
  let authPlain: Buffer;
  try { authPlain = aesEcbDecryptBlock(vmessKdf16(cmdKey, KDF_AUTH_ID), authId); }
  catch { return null; }

  const ts = Number(authPlain.readBigInt64BE(0));
  if (crc32(authPlain.subarray(0, 12)) !== authPlain.readUInt32BE(12)) return null;
  if (Math.abs(ts - nowSec) > 120) return null;
  if (data.length < 42) return null;

  const encLen = data.subarray(16, 34);
  const connNonce = data.subarray(34, 42);

  let plainLen: number;
  try {
    const lp = aeadOpen(SEC_AES128_GCM,
      vmessKdf16(cmdKey, KDF_HDR_LEN_KEY, authId, connNonce),
      vmessKdf(cmdKey, KDF_HDR_LEN_IV, authId, connNonce).subarray(0, 12),
      encLen, authId);
    plainLen = (lp[0] << 8) | lp[1];
  } catch { return null; }

  const total = 42 + plainLen + 16;
  if (data.length < total) return null;

  let plain: Buffer;
  try {
    plain = aeadOpen(SEC_AES128_GCM,
      vmessKdf16(cmdKey, KDF_HDR_KEY, authId, connNonce),
      vmessKdf(cmdKey, KDF_HDR_IV, authId, connNonce).subarray(0, 12),
      data.subarray(42, total), authId);
  } catch { return null; }

  const rbi = Buffer.from(plain.subarray(1, 17));
  const rbk = Buffer.from(plain.subarray(17, 33));
  const respHdr = plain[33];
  let option = plain[34];
  const wireSec = plain[35] & 0x0f;
  const command = plain[37];

  let security = wireSec;
  if (security === SEC_ZERO) {
    security = SEC_NONE;
    option &= ~(OPT_CHUNK_STREAM | OPT_CHUNK_MASKING | OPT_GLOBAL_PADDING | OPT_AUTHENTICATED_LENGTH);
  }

  let p = 38;
  let address = 'v1.mux.cool', port = 0, atyp = ATYP_DOMAIN;
  if (command !== CMD_MUX) {
    port = (plain[p] << 8) | plain[p + 1]; p += 2;
    atyp = plain[p]; p += 1;
    const r = parseAddress(plain, p, atyp);
    if (!r) throw new Error('truncated destination');
    [address, p] = r;
  }

  const cp = plain.length - 4;
  if (fnv1a32(plain.subarray(0, cp)) !== plain.readUInt32BE(cp)) {
    throw new Error('invalid VMess checksum');
  }

  return {
    command, address, port, addressType: atyp,
    option, security, wireSecurity: wireSec,
    requestBodyIv: rbi, requestBodyKey: rbk,
    responseHeader: respHdr, headerLength: total, authId,
    responseBodyKey: sha256(rbk).subarray(0, 16),
    responseBodyIv: sha256(rbi).subarray(0, 16),
  };
}

// ============ VMess body decoder / encoder ============
class VmessBodyDecoder {
  private h: VmessHeader;
  private pending = Buffer.alloc(0);
  private awaiting: { size: number; padding: number } | null = null;
  private done = false;
  private zeroRaw: boolean;
  private sizeShake: ShakeSizeParser | null;
  private paddingShake: ShakeSizeParser | null;
  private bodyNonce: NonceCounter;
  private lengthNonce: NonceCounter;
  private authLength: boolean;
  private authLengthKey: Buffer | null;

  constructor(h: VmessHeader) {
    this.h = h;
    this.zeroRaw = h.wireSecurity === SEC_ZERO ||
      (h.security === SEC_NONE && !(h.option & OPT_CHUNK_STREAM));
    this.sizeShake = (h.option & OPT_CHUNK_MASKING) ? new ShakeSizeParser(h.requestBodyIv) : null;
    this.paddingShake = (h.option & OPT_GLOBAL_PADDING) ? this.sizeShake : null;
    this.bodyNonce = new NonceCounter(h.requestBodyIv);
    this.lengthNonce = new NonceCounter(h.requestBodyIv);
    this.authLength = !!(h.option & OPT_AUTHENTICATED_LENGTH) &&
      (h.security === SEC_AES128_GCM || h.security === SEC_CHACHA20_POLY1305);
    this.authLengthKey = this.authLength ? vmessKdf16(h.requestBodyKey, KDF_AUTH_LEN) : null;
  }

  push(chunk: Buffer): Buffer[] {
    if (this.done) return [];
    if (this.zeroRaw) return chunk.length ? [chunk] : [];
    this.pending = Buffer.concat([this.pending, chunk]);
    const out: Buffer[] = [];
    while (true) {
      if (!this.awaiting) {
        const sbLen = this.authLength ? 18 : 2;
        if (this.pending.length < sbLen) break;
        let padding = 0;
        if (this.paddingShake && this.h.security !== SEC_NONE) {
          padding = this.paddingShake.nextPaddingLen();
        }
        const raw = this.pending.subarray(0, sbLen);
        let size: number;
        if (this.authLength) {
          const pl = aeadOpen(this.h.security, this.authLengthKey!, this.lengthNonce.next(12), raw);
          size = ((pl[0] << 8) | pl[1]) + 16;
        } else if (this.sizeShake) {
          size = this.sizeShake.decodeSize(raw);
        } else {
          size = (raw[0] << 8) | raw[1];
        }
        this.pending = this.pending.subarray(sbLen);
        this.awaiting = { size, padding };
      }
      const { size, padding } = this.awaiting;
      if (this.pending.length < size) break;
      const frame = this.pending.subarray(0, size);
      this.pending = this.pending.subarray(size);
      this.awaiting = null;
      if (this.h.security === SEC_NONE) {
        if (size === 0) { this.done = true; break; }
        out.push(Buffer.from(frame));
        continue;
      }
      if (size === 16 + padding) { this.done = true; break; }
      out.push(aeadOpen(this.h.security, this.h.requestBodyKey,
        this.bodyNonce.next(12), frame.subarray(0, size - padding)));
    }
    return out;
  }
}

class VmessBodyEncoder {
  private h: VmessHeader;
  private responseKey: Buffer;
  private responseIv: Buffer;
  private zeroRaw: boolean;
  private sizeShake: ShakeSizeParser | null;
  private paddingShake: ShakeSizeParser | null;
  private bodyNonce: NonceCounter;
  private lengthNonce: NonceCounter;
  private authLength: boolean;
  private authLengthKey: Buffer | null;

  constructor(h: VmessHeader) {
    this.h = h;
    this.responseKey = h.responseBodyKey;
    this.responseIv = h.responseBodyIv;
    this.zeroRaw = h.wireSecurity === SEC_ZERO ||
      (h.security === SEC_NONE && !(h.option & OPT_CHUNK_STREAM));
    this.sizeShake = (h.option & OPT_CHUNK_MASKING) ? new ShakeSizeParser(this.responseIv) : null;
    this.paddingShake = (h.option & OPT_GLOBAL_PADDING) ? this.sizeShake : null;
    this.bodyNonce = new NonceCounter(this.responseIv);
    this.lengthNonce = new NonceCounter(h.requestBodyIv);
    this.authLength = !!(h.option & OPT_AUTHENTICATED_LENGTH) &&
      (h.security === SEC_AES128_GCM || h.security === SEC_CHACHA20_POLY1305);
    this.authLengthKey = this.authLength ? vmessKdf16(h.requestBodyKey, KDF_AUTH_LEN) : null;
  }

  encode(data: Buffer): Buffer {
    if (this.zeroRaw) return data;
    const units: Buffer[] = [];
    for (let o = 0; o < data.length; o += 8192) {
      units.push(this.unit(data.subarray(o, o + 8192)));
    }
    return Buffer.concat(units);
  }

  private unit(p: Buffer): Buffer {
    if (this.h.security === SEC_NONE) {
      const size = p.length;
      const sb = this.sizeShake ? this.sizeShake.encodeSize(size)
        : Buffer.from([size >> 8, size & 0xff]);
      return Buffer.concat([sb, p]);
    }
    const padding = this.paddingShake ? this.paddingShake.nextPaddingLen() : 0;
    const sealed = aeadSeal(this.h.security, this.responseKey, this.bodyNonce.next(12), p);
    const size = sealed.length + padding;
    let sb: Buffer;
    if (this.authLength) {
      const ps = size - 16;
      sb = aeadSeal(this.h.security, this.authLengthKey!, this.lengthNonce.next(12),
        Buffer.from([ps >> 8, ps & 0xff]));
    } else if (this.sizeShake) {
      sb = this.sizeShake.encodeSize(size);
    } else {
      sb = Buffer.from([size >> 8, size & 0xff]);
    }
    return Buffer.concat([sb, sealed, padding ? crypto.randomBytes(padding) : Buffer.alloc(0)]);
  }
}

function encodeVmessResponseHeader(h: VmessHeader): Buffer {
  const plain = Buffer.from([h.responseHeader, 0, 0, 0]);
  const lenPlain = Buffer.from([0, plain.length]);
  return Buffer.concat([
    aeadSeal(SEC_AES128_GCM,
      vmessKdf16(h.responseBodyKey, KDF_RESP_LEN_KEY),
      vmessKdf(h.responseBodyIv, KDF_RESP_LEN_IV).subarray(0, 12),
      lenPlain),
    aeadSeal(SEC_AES128_GCM,
      vmessKdf16(h.responseBodyKey, KDF_RESP_KEY),
      vmessKdf(h.responseBodyIv, KDF_RESP_IV).subarray(0, 12),
      plain),
  ]);
}

// ============ Network helpers ============
async function resolveHost(host: string): Promise<string> {
  if (IPV4_REGEX.test(host)) return host;
  try {
    const r = await Promise.race([
      dnsPromises.lookup(host, { family: 4 }),
      new Promise<never>((_, rej) => setTimeout(() => rej(new Error('timeout')), 4000)),
    ]);
    return r.address;
  } catch {}
  try {
    const r = await fetch(
      `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`,
      { headers: { Accept: 'application/dns-json' }, signal: AbortSignal.timeout(5000) },
    );
    const d: any = await r.json();
    if (d.Status === 0) {
      for (const a of d.Answer || []) if (a.type === 1) return a.data;
    }
  } catch {}
  return host;
}

function connectTcp(host: string, port: number): Promise<net.Socket> {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host, port }, () => resolve(s));
    s.once('error', reject);
  });
}

// ============ Handlers ============
interface Prepared {
  socket: net.Socket;
  initial?: Buffer;
  decoder?: VmessBodyDecoder;
  encoder?: VmessBodyEncoder;
}

async function prepareVless(ws: WebSocket, msg: Buffer): Promise<Prepared | null> {
  if (msg.length < 18) return null;
  const version = msg[0];
  const clientUuid = msg.subarray(1, 17);
  if (!ALLOW_ANY_UUID && !clientUuid.equals(UUID_BYTES)) return null;
  let i = 18 + msg[17] + 1;
  if (msg.length < i + 3) return null;
  const port = msg.readUInt16BE(i); i += 2;
  const atyp = msg[i]; i += 1;

  let host: string;
  if (atyp === 1) {
    if (msg.length < i + 4) return null;
    host = Array.from(msg.subarray(i, i + 4)).join('.'); i += 4;
  } else if (atyp === 2) {
    if (msg.length < i + 1) return null;
    const L = msg[i]; i += 1;
    if (msg.length < i + L) return null;
    host = msg.subarray(i, i + L).toString('utf-8'); i += L;
  } else if (atyp === 3) {
    if (msg.length < i + 16) return null;
    const parts: string[] = [];
    for (let j = 0; j < 16; j += 2) parts.push(msg.readUInt16BE(i + j).toString(16));
    host = parts.join(':'); i += 16;
  } else return null;

  if (isBlockedDomain(host)) return null;
  try { ws.send(Buffer.from([version, 0])); } catch { return null; }

  const target = await resolveHost(host);
  let socket: net.Socket;
  try { socket = await connectTcp(target, port); } catch { return null; }
  return { socket, initial: msg.subarray(i) };
}

async function prepareTrojan(ws: WebSocket, msg: Buffer): Promise<Prepared | null> {
  if (msg.length < 58) return null;
  const received = msg.subarray(0, 56).toString('ascii');
  if (!ALLOW_ANY_UUID) {
    const expected = crypto.createHash('sha224').update(UUID).digest('hex');
    if (received !== expected) return null;
  }
  let off = 56;
  if (off + 1 < msg.length && msg[off] === 0x0d && msg[off + 1] === 0x0a) off += 2;
  if (off >= msg.length || msg[off] !== 0x01) return null;
  off += 1;
  if (off >= msg.length) return null;
  const atyp = msg[off]; off += 1;

  let host: string;
  if (atyp === 0x01) {
    if (msg.length < off + 4) return null;
    host = Array.from(msg.subarray(off, off + 4)).join('.'); off += 4;
  } else if (atyp === 0x03) {
    if (msg.length < off + 1) return null;
    const L = msg[off]; off += 1;
    if (msg.length < off + L) return null;
    host = msg.subarray(off, off + L).toString('utf-8'); off += L;
  } else if (atyp === 0x04) {
    if (msg.length < off + 16) return null;
    const parts: string[] = [];
    for (let j = 0; j < 16; j += 2) parts.push(msg.readUInt16BE(off + j).toString(16));
    host = parts.join(':'); off += 16;
  } else return null;

  if (msg.length < off + 2) return null;
  const port = msg.readUInt16BE(off); off += 2;
  if (off + 1 < msg.length && msg[off] === 0x0d && msg[off + 1] === 0x0a) off += 2;
  if (isBlockedDomain(host)) return null;

  const target = await resolveHost(host);
  let socket: net.Socket;
  try { socket = await connectTcp(target, port); } catch { return null; }
  return { socket, initial: msg.subarray(off) };
}

async function prepareVmess(ws: WebSocket, msg: Buffer): Promise<Prepared | null> {
  let header: VmessHeader | null;
  try { header = tryParseVmessHeader(msg, UUID_BYTES); }
  catch (e) { logErr('[VMESS PARSE]', e); return null; }
  if (!header) return null;
  if (isBlockedDomain(header.address)) return null;

  const decoder = new VmessBodyDecoder(header);
  const encoder = new VmessBodyEncoder(header);
  try { ws.send(encodeVmessResponseHeader(header)); } catch { return null; }

  const target = await resolveHost(header.address);
  let socket: net.Socket;
  try { socket = await connectTcp(target, header.port); } catch { return null; }
  return { socket, initial: msg.subarray(header.headerLength), decoder, encoder };
}

// ============ HTTP + WebSocket server ============
const server = createServer((req: IncomingMessage, res: ServerResponse) => {
  const path = new URL(req.url || '/', 'http://x').pathname;
  if (path === '/') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('server is running');
    return;
  }
  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  const path = new URL(req.url || '/', 'http://x').pathname;
  if (path === '/vless' || path === '/trojan' || path === '/vmess') {
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
  } else {
    socket.destroy();
  }
});

wss.on('connection', (ws: WebSocket, req: IncomingMessage) => {
  const path = new URL(req.url || '/', 'http://x').pathname;

  const pending: Buffer[] = [];
  let firstMsgResolve: ((b: Buffer) => void) | null = null;
  let firstMsgReject: ((e: Error) => void) | null = null;
  let bufferHandler: ((b: Buffer) => void) | null = null;
  let gotFirst = false;

  const firstMsgPromise = new Promise<Buffer>((res, rej) => {
    firstMsgResolve = res;
    firstMsgReject = rej;
  });

  ws.on('message', (data: Buffer) => {
    if (!gotFirst && firstMsgResolve) {
      gotFirst = true;
      const r = firstMsgResolve; firstMsgResolve = null; firstMsgReject = null;
      r(data);
      return;
    }
    if (bufferHandler) bufferHandler(data);
    else pending.push(data);
  });

  ws.once('close', () => {
    if (firstMsgReject) firstMsgReject(new Error('closed'));
  });

  (async () => {
    let prepared: Prepared | null = null;
    try {
      const msg = await firstMsgPromise;
      if (path === '/vless') prepared = await prepareVless(ws, msg);
      else if (path === '/trojan') prepared = await prepareTrojan(ws, msg);
      else if (path === '/vmess') prepared = await prepareVmess(ws, msg);
    } catch (e) { logErr('[CONN]', e); }

    if (!prepared) {
      try { ws.close(); } catch {}
      return;
    }

    let closed = false;
    const cleanup = () => {
      if (closed) return;
      closed = true;
      try { ws.close(); } catch {}
      try { prepared!.socket.destroy(); } catch {}
    };

    bufferHandler = (data: Buffer) => {
      if (closed) return;
      try {
        if (prepared!.decoder) {
          for (const p of prepared!.decoder.push(data)) prepared!.socket.write(p);
        } else {
          prepared!.socket.write(data);
        }
      } catch (e) { logErr('[WS->TCP]', e); cleanup(); }
    };

    prepared.socket.on('data', (data: Buffer) => {
      if (closed) return;
      try {
        const payload = prepared!.encoder ? prepared!.encoder.encode(data) : data;
        if (payload.length) ws.send(payload);
      } catch (e) { logErr('[TCP->WS]', e); cleanup(); }
    });
    prepared.socket.once('close', cleanup);
    prepared.socket.once('error', cleanup);
    ws.once('close', cleanup);
    ws.once('error', cleanup);

    if (prepared.initial && prepared.initial.length) bufferHandler(prepared.initial);
    for (const m of pending) bufferHandler(m);
    pending.length = 0;
  })();
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[VLESS/Trojan/VMess] listening on 0.0.0.0:${PORT}`);
});
