// @ts-check
// Parsing, verification and modelling of airlock session logs. Pure
// functions, no DOM: the same module runs under `node --test`.

const HASH_SUFFIX = ',"hash":"'.length + 64 + '"}'.length;
const ZERO_HASH = '0'.repeat(64);
const enc = new TextEncoder();

/** @param {ArrayBuffer} buf */
function hex(buf) {
  return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
}

/** @param {string} s */
async function sha256hex(s) {
  return hex(await crypto.subtle.digest('SHA-256', enc.encode(s)));
}

/** @param {string} b64 */
function fromBase64(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Split a log into non-empty lines, keeping 1-based line numbers.
 * @param {string} text
 */
export function splitLines(text) {
  const out = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i].replace(/\r$/, '');
    if (raw.trim() !== '') out.push({ line: i + 1, raw });
  }
  return out;
}

/**
 * The bytes a record's hash covers: the line with its hash member removed.
 * @param {string} raw
 */
export function hashedBody(raw) {
  if (raw.length < HASH_SUFFIX + 2 || raw.slice(raw.length - HASH_SUFFIX, raw.length - HASH_SUFFIX + 9) !== ',"hash":"' || !raw.endsWith('"}')) {
    return null;
  }
  return { body: raw.slice(0, raw.length - HASH_SUFFIX) + '}', claimed: raw.slice(raw.length - HASH_SUFFIX + 9, raw.length - 2) };
}

/**
 * Check the hash chain and, where the browser can, the signatures. Mirrors
 * `airlock verify`; the Go implementation is the reference.
 * @param {{line:number, raw:string}[]} lines
 */
export async function verify(lines) {
  /** @type {{line:number, msg:string}[]} */
  const problems = [];
  let prev = ZERO_HASH;
  let key = null;
  let keyText = '';
  let sigSupport = true;
  let sigsValid = 0;
  let sigsBad = 0;
  let signedUpTo = 0;
  let closed = false;
  for (let i = 0; i < lines.length; i++) {
    const { line, raw } = lines[i];
    const parts = hashedBody(raw);
    let rec;
    try {
      rec = JSON.parse(raw);
    } catch {
      problems.push({ line, msg: 'not valid JSON' });
      continue;
    }
    if (!parts) {
      problems.push({ line, msg: 'record does not end with a hash member' });
      continue;
    }
    if ((await sha256hex(parts.body)) !== parts.claimed) problems.push({ line, msg: 'hash mismatch: the record was changed after it was written' });
    if (rec.prev !== prev) problems.push({ line, msg: 'chain broken: prev does not match the record before it' });
    if (rec.seq !== i) problems.push({ line, msg: `sequence number ${rec.seq}, expected ${i}` });
    if (i === 0 && rec.kind !== 'open') problems.push({ line, msg: 'the first record is not an open record' });
    if (rec.kind === 'open' && rec.session?.key) {
      keyText = rec.session.key;
      try {
        key = await crypto.subtle.importKey('raw', fromBase64(keyText.replace(/^ed25519:/, '')), { name: 'Ed25519' }, false, ['verify']);
      } catch {
        sigSupport = false;
      }
    }
    if (rec.kind === 'checkpoint' || rec.kind === 'close') {
      if (rec.kind === 'close') closed = true;
      if (key && rec.sig) {
        const msg = enc.encode(`airlock ${rec.kind} v1\n${rec.seq}\n${rec.prev}`);
        let ok = false;
        try {
          ok = await crypto.subtle.verify({ name: 'Ed25519' }, key, fromBase64(rec.sig), msg);
        } catch {
          sigSupport = false;
        }
        if (ok) {
          sigsValid++;
          signedUpTo = i + 1;
        } else if (sigSupport) {
          sigsBad++;
          problems.push({ line, msg: `bad signature on ${rec.kind} record` });
        }
      }
    }
    prev = parts.claimed;
  }
  return {
    ok: problems.length === 0,
    records: lines.length,
    head: prev,
    problems,
    closed,
    signature: keyText ? { key: keyText, checked: sigSupport && !!key, valid: sigsValid, bad: sigsBad, upTo: signedUpTo } : null,
  };
}

/**
 * Parse every line that is JSON; lines that are not stay as problems for
 * verify() to report.
 * @param {{line:number, raw:string}[]} lines
 */
export function parseRecords(lines) {
  const out = [];
  for (const { line, raw } of lines) {
    try {
      out.push({ ...JSON.parse(raw), line });
    } catch {
      /* reported by verify */
    }
  }
  return out;
}

/** @param {any} m */
function kindOf(m) {
  if (!m || typeof m !== 'object' || Array.isArray(m)) return 'invalid';
  if (typeof m.method === 'string') return m.id === undefined || m.id === null ? 'notification' : 'request';
  if ('result' in m || 'error' in m) return 'response';
  return 'invalid';
}

const DIR_FROM = { c2s: 'client', c2a: 'client', s2c: 'server', s2a: 'server', a2c: 'airlock' };

/**
 * Turn records into rows for the timeline: request/response pairs become
 * one row, airlock's events attach to the call they concern, everything
 * else stands on its own.
 * @param {any[]} records
 */
export function buildModel(records) {
  const open = records.find((r) => r.kind === 'open');
  const close = records.find((r) => r.kind === 'close');
  const t0 = open ? Date.parse(open.ts) : records.length ? Date.parse(records[0].ts) : 0;
  /** @type {any[]} */
  const rows = [];
  /** @type {Map<string, any>} */
  const pending = new Map();
  const model = {
    session: open?.session ?? null,
    exit: close?.exit,
    durationMs: close && open ? Date.parse(close.ts) - Date.parse(open.ts) : null,
    protocol: '',
    server: null,
    tools: /** @type {Map<string, any>} */ (new Map()),
    counts: { calls: 0, blocked: 0, errors: 0, redacted: 0, drift: 0, suspicious: 0, stderr: 0, messages: 0 },
    rows,
  };
  const at = (/** @type {any} */ r) => Date.parse(r.ts) - t0;
  let lastList = null;

  /** @param {any} m @param {any} rec @param {string} dir */
  function onMessage(m, rec, dir) {
    const k = kindOf(m);
    const from = DIR_FROM[dir] ?? 'client';
    if (k === 'request') {
      const key = (from === 'server' ? 's:' : 'c:') + JSON.stringify(m.id);
      const row = {
        type: 'call', seq: rec.seq, t: at(rec), from, id: m.id, method: m.method,
        tool: m.method === 'tools/call' ? m.params?.name : undefined,
        req: m, resp: null, respFrom: '', latency: null, status: 'pending', events: [], stopped: dir === 'c2a',
      };
      if (m.method === 'tools/call') model.counts.calls++;
      pending.set(key, row);
      rows.push(row);
      return;
    }
    if (k === 'response') {
      // A response from the server answers a client request; a response
      // from the client answers a server request; airlock answers clients.
      const key = (from === 'client' ? 's:' : 'c:') + JSON.stringify(m.id);
      const row = pending.get(key);
      if (!row) {
        rows.push({ type: 'orphan', seq: rec.seq, t: at(rec), from, msg: m });
        return;
      }
      pending.delete(key);
      row.resp = m;
      row.respFrom = from;
      row.respSeq = rec.seq;
      row.latency = at(rec) - row.t;
      if (from === 'airlock') row.status = 'blocked';
      else if (m.error || m.result?.isError) row.status = 'error';
      else row.status = 'ok';
      if (row.status === 'blocked') model.counts.blocked++;
      if (row.status === 'error') model.counts.errors++;
      if (row.method === 'initialize' && m.result) {
        model.server = m.result.serverInfo ?? model.server;
        model.protocol = m.result.protocolVersion ?? model.protocol;
      }
      if (row.method === 'server/discover' && m.result) {
        model.server = m.result.serverInfo ?? model.server;
      }
      const si = m.result?._meta?.['io.modelcontextprotocol/serverInfo'];
      if (si) model.server = si;
      if (row.method === 'tools/list' && Array.isArray(m.result?.tools)) {
        for (const t of m.result.tools) model.tools.set(t.name, t);
        lastList = row;
      }
      return;
    }
    rows.push({ type: k === 'notification' ? 'notification' : 'invalid', seq: rec.seq, t: at(rec), from, method: m?.method, msg: m, stopped: dir === 'c2a' || dir === 's2a' });
  }

  for (const rec of records) {
    switch (rec.kind) {
      case 'msg': {
        model.counts.messages++;
        if ('msg' in rec && Array.isArray(rec.msg)) {
          for (const m of rec.msg) onMessage(m, rec, rec.dir);
        } else if ('msg' in rec) {
          onMessage(rec.msg, rec, rec.dir);
        } else {
          rows.push({ type: 'invalid', seq: rec.seq, t: at(rec), from: DIR_FROM[rec.dir] ?? 'client', text: rec.msg_text, stopped: rec.dir === 'c2a' });
        }
        break;
      }
      case 'event': {
        const ev = rec.event ?? {};
        if (ev.type === 'protocol' && ev.version) model.protocol = ev.version;
        if (ev.type === 'drift') model.counts.drift++;
        if (ev.type === 'suspicious' && (ev.flags ?? []).some((/** @type {any} */ f) => f.severity === 'high')) model.counts.suspicious++;
        if (ev.type === 'redact') model.counts.redacted++;
        const target = ev.id !== undefined ? pending.get('c:' + JSON.stringify(ev.id)) ?? findCall(rows, ev.id) : null;
        if (target) {
          target.events.push({ ...ev, seq: rec.seq });
          if (ev.type === 'redact') target.redacted = true;
          if (ev.type === 'allow' || ev.type === 'deny') target.decision = ev;
          break;
        }
        if (['pin', 'drift', 'suspicious', 'new_tool', 'removed', 'repin'].includes(ev.type) && lastList && rec.seq - (lastList.respSeq ?? 0) < 64) {
          lastList.events.push({ ...ev, seq: rec.seq });
        }
        const noteOnly = ev.type === 'suspicious' && ev.action === 'note';
        if (ev.type !== 'pin' && ev.type !== 'protocol' && !noteOnly) {
          rows.push({ type: 'event', seq: rec.seq, t: at(rec), event: ev });
        }
        break;
      }
      case 'stderr':
        model.counts.stderr++;
        rows.push({ type: 'stderr', seq: rec.seq, t: at(rec), text: rec.line_text ?? '' });
        break;
      case 'open':
      case 'close':
        rows.push({ type: rec.kind, seq: rec.seq, t: at(rec), rec });
        break;
    }
  }
  return model;
}

/** @param {any[]} rows @param {any} id */
function findCall(rows, id) {
  const key = JSON.stringify(id);
  for (let i = rows.length - 1; i >= 0; i--) {
    const r = rows[i];
    if (r.type === 'call' && r.from === 'client' && JSON.stringify(r.id) === key) return r;
  }
  return null;
}

/**
 * Split a string into visible text and the characters that hide text:
 * Unicode tag characters (decoded back to the ASCII they smuggle) and
 * zero-width or bidi controls.
 * @param {string} s
 * @returns {{text:string, hidden?:'tag'|'invisible'}[]}
 */
export function revealHidden(s) {
  /** @type {{text:string, hidden?:'tag'|'invisible'}[]} */
  const out = [];
  let buf = '';
  let mode = /** @type {''|'tag'|'invisible'} */ ('');
  const flush = () => {
    if (buf) out.push(mode ? { text: buf, hidden: mode } : { text: buf });
    buf = '';
  };
  for (const ch of s) {
    const cp = /** @type {number} */ (ch.codePointAt(0));
    let m = /** @type {''|'tag'|'invisible'} */ ('');
    let shown = ch;
    if (cp >= 0xe0000 && cp <= 0xe007f) {
      m = 'tag';
      shown = cp >= 0xe0020 && cp <= 0xe007e ? String.fromCodePoint(cp - 0xe0000) : '';
    } else if ((cp >= 0x200b && cp <= 0x200f) || (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x2064) || (cp >= 0x2066 && cp <= 0x2069) || cp === 0xfeff || cp === 0xad) {
      m = 'invisible';
      shown = `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`;
    }
    if (m !== mode) {
      flush();
      mode = m;
    }
    buf += m === 'invisible' ? (buf ? ' ' : '') + shown : shown;
  }
  flush();
  return out;
}

/**
 * Longest-common-subsequence diff of two token lists.
 * @param {string[]} a
 * @param {string[]} b
 * @returns {{op:'eq'|'del'|'ins', text:string}[]}
 */
export function diff(a, b) {
  const n = a.length;
  const m = b.length;
  if (n * m > 4_000_000) {
    return [...a.map((text) => ({ op: /** @type {const} */ ('del'), text })), ...b.map((text) => ({ op: /** @type {const} */ ('ins'), text }))];
  }
  const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  /** @type {{op:'eq'|'del'|'ins', text:string}[]} */
  const out = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ op: 'eq', text: a[i] });
      i++;
      j++;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      out.push({ op: 'del', text: a[i++] });
    } else {
      out.push({ op: 'ins', text: b[j++] });
    }
  }
  while (i < n) out.push({ op: 'del', text: a[i++] });
  while (j < m) out.push({ op: 'ins', text: b[j++] });
  return out;
}

/** Words and the spaces between them, so a word diff can be re-joined. @param {string} s */
export function words(s) {
  return s.match(/\s+|[^\s]+/g) ?? [];
}
