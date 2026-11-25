// @ts-check
import { buildModel, diff, parseRecords, revealHidden, splitLines, verify, words } from './log.js';

/** @typedef {{name:string, url?:string, file?:File, note?:string}} Source */

const $ = (/** @type {string} */ sel) => /** @type {HTMLElement} */ (document.querySelector(sel));

/**
 * Tiny element builder. Children that are strings become text nodes, so
 * nothing from a log is ever parsed as HTML.
 * @param {string} tag
 * @param {Record<string, any>|null} [attrs]
 * @param {...any} children
 */
function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat(Infinity)) {
    if (c === undefined || c === null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const state = {
  /** @type {Source[]} */ sources: [],
  /** @type {Source|null} */ current: null,
  /** @type {any} */ model: null,
  /** @type {any} */ integrity: null,
  filter: 'all',
  query: '',
  /** @type {number|null} */ selected: null,
  remote: false,
};

// ---------------------------------------------------------------- loading

async function discover() {
  // config.json is a static file saying "samples"; airlock view answers the
  // same path with "local". Either way the page makes no request that 404s.
  let source = 'samples';
  try {
    source = (await (await fetch('config.json', { cache: 'no-store' })).json()).source;
  } catch {
    /* opened from disk or an odd host: try samples */
  }
  if (source === 'local') {
    const j = await (await fetch('api/sessions', { cache: 'no-store' })).json();
    state.remote = true;
    return j.sessions.map((/** @type {any} */ s) => ({ name: s.name, url: s.url }));
  }
  try {
    const r = await fetch('samples/index.json');
    if (r.ok) {
      const j = await r.json();
      return j.samples.map((/** @type {any} */ s) => ({ name: s.name, url: 'samples/' + s.file, note: s.title }));
    }
  } catch {
    /* no samples */
  }
  return [];
}

/** @param {Source} src */
async function load(src) {
  state.current = src;
  state.selected = null;
  $('#status').textContent = 'Loading…';
  let text;
  try {
    text = src.file ? await src.file.text() : await (await fetch(/** @type {string} */ (src.url), { cache: 'no-store' })).text();
  } catch (e) {
    $('#status').textContent = `Could not read ${src.name}: ${e}`;
    return;
  }
  const lines = splitLines(text);
  state.model = buildModel(parseRecords(lines));
  state.integrity = null;
  renderPicker();
  renderSummary();
  renderList();
  const fromHash = new URLSearchParams(location.hash.slice(1)).get('r');
  const first = fromHash !== null ? Number(fromHash) : defaultSelection();
  select(first, true);
  $('#status').textContent = '';
  verify(lines).then((res) => {
    if (state.current !== src) return;
    state.integrity = res;
    renderIntegrity();
  });
}

function defaultSelection() {
  const rows = state.model.rows;
  const interesting = rows.find((/** @type {any} */ r) => r.type === 'event' && r.event.type === 'drift') ?? rows.find((/** @type {any} */ r) => r.status === 'blocked') ?? rows.find((/** @type {any} */ r) => r.type === 'call');
  return interesting ? interesting.seq : null;
}

// --------------------------------------------------------------- summary

function renderPicker() {
  const sel = /** @type {HTMLSelectElement} */ ($('#session'));
  sel.replaceChildren(...state.sources.map((s, i) => h('option', { value: i, selected: s === state.current }, s.note ? `${s.note} (${s.name})` : s.name)));
  sel.hidden = state.sources.length === 0;
}

function renderSummary() {
  const m = state.model;
  const s = m.session ?? {};
  const cmd = (s.cmd ?? []).join(' ');
  const facts = [];
  if (m.server?.name) facts.push(`${m.server.name}${m.server.version ? ' ' + m.server.version : ''}`);
  if (m.protocol) facts.push(`MCP ${m.protocol}`);
  facts.push(`${m.counts.messages} messages`);
  if (m.durationMs !== null) facts.push(fmtDuration(m.durationMs));
  if (m.exit !== undefined) facts.push(`exit ${m.exit}`);
  if (s.policy) facts.push(`policy ${basename(s.policy)}`);
  if (s.airlock) facts.push(`airlock ${s.airlock}`);

  const tallies = [
    ['calls', m.counts.calls, 'tool calls', ''],
    ['blocked', m.counts.blocked, 'blocked', 'bad'],
    ['redacted', m.counts.redacted, 'redacted', 'warn'],
    ['drift', m.counts.drift, 'changed tools', 'drift'],
    ['suspicious', m.counts.suspicious, 'suspicious tools', 'warn'],
  ].filter(([, n], i) => i === 0 || Number(n) > 0);

  $('#summary').replaceChildren(
    h('div', { class: 'cmd', title: cmd }, h('span', { class: 'prompt' }, '$ '), cmd || '(no command recorded)'),
    h('div', { class: 'facts' }, facts.map((f) => h('span', null, f))),
    h('div', { class: 'tallies' }, tallies.map(([k, n, label, tone]) => h('button', { class: `tally ${tone}`, onclick: () => setFilter(k === 'calls' ? 'calls' : 'flagged') }, h('b', null, String(n)), ' ', label))),
    h('div', { id: 'integrity', class: 'integrity pending' }, 'Verifying hash chain…'),
  );
}

function renderIntegrity() {
  const r = state.integrity;
  const el = $('#integrity');
  if (!r) return;
  const parts = [];
  if (r.ok) parts.push(h('span', { class: 'ok' }, `Chain intact, ${r.records} records`));
  else parts.push(h('span', { class: 'bad' }, `Chain broken: ${r.problems[0].msg} (line ${r.problems[0].line})`));
  if (r.signature) {
    const sig = r.signature;
    const short = sig.key.slice(0, 18) + '…';
    if (!sig.checked) parts.push(h('span', { class: 'note', title: sig.key }, `signed by ${short}, signatures not checked (this browser has no Ed25519; use airlock verify)`));
    else if (sig.bad) parts.push(h('span', { class: 'bad', title: sig.key }, `${sig.bad} bad signature(s)`));
    else parts.push(h('span', { class: 'ok', title: sig.key }, `${sig.valid} signature(s) valid, key ${short}`));
  } else {
    parts.push(h('span', { class: 'note' }, 'unsigned'));
  }
  if (!r.closed) parts.push(h('span', { class: 'note' }, 'no closing record'));
  el.className = 'integrity ' + (r.ok ? 'ok' : 'bad');
  el.replaceChildren(...parts.flatMap((p, i) => (i ? [h('span', { class: 'sep' }, '·'), p] : [p])));
  el.title = `head ${r.head}`;
}

// ------------------------------------------------------------------ list

/** @param {string} f */
function setFilter(f) {
  state.filter = f;
  for (const b of document.querySelectorAll('#filters button')) b.classList.toggle('on', /** @type {HTMLElement} */ (b).dataset.f === f);
  renderList();
}

/** @param {any} r */
function visible(r) {
  switch (state.filter) {
    case 'calls':
      return r.type === 'call' && r.method === 'tools/call';
    case 'flagged':
      return r.status === 'blocked' || r.redacted || (r.type === 'event' && r.event.type !== 'allow') || r.type === 'invalid';
    case 'protocol':
      return r.type === 'call' || r.type === 'notification' || r.type === 'orphan' || r.type === 'invalid';
    case 'stderr':
      return r.type === 'stderr';
  }
  return true;
}

/** @param {any} r */
function matches(r) {
  if (!state.query) return true;
  const q = state.query.toLowerCase();
  return JSON.stringify([r.method, r.tool, r.text, r.req, r.resp, r.event, r.msg]).toLowerCase().includes(q);
}

function renderList() {
  const rows = state.model.rows.filter((/** @type {any} */ r) => visible(r) && matches(r));
  const maxLatency = Math.max(1, ...rows.filter((/** @type {any} */ r) => r.latency !== null && r.latency !== undefined).map((/** @type {any} */ r) => r.latency));
  const list = $('#rows');
  list.replaceChildren(...rows.map((/** @type {any} */ r) => rowEl(r, maxLatency)));
  $('#count').textContent = `${rows.length} of ${state.model.rows.length}`;
  markSelected();
}

/** @param {any} r @param {number} maxLatency */
function rowEl(r, maxLatency) {
  const sel = () => select(r.seq);
  const time = h('span', { class: 'time' }, fmtOffset(r.t));
  switch (r.type) {
    case 'call': {
      const lat = r.latency ?? null;
      const bar = h('span', { class: 'bar' });
      if (lat !== null) bar.style.setProperty('--w', `${Math.max(2, (lat / maxLatency) * 100)}%`);
      return h('li', { class: `row call ${r.status} from-${r.from}`, dataset: { seq: r.seq }, onclick: sel },
        time,
        h('span', { class: 'arrow' }, r.from === 'server' ? '←' : '→'),
        h('span', { class: 'what' },
          r.tool ? h('b', null, r.tool) : h('b', { class: 'method' }, r.method),
          r.tool ? h('span', { class: 'sub' }, argSummary(r.req?.params?.arguments)) : null),
        h('span', { class: 'chips' }, r.redacted ? chip('redacted', 'warn') : null, statusChip(r)),
        h('span', { class: 'lat' }, lat === null ? '' : fmtMs(lat), bar));
    }
    case 'notification':
    case 'orphan':
    case 'invalid':
      return h('li', { class: `row note from-${r.from}${r.stopped ? ' stopped' : ''}`, dataset: { seq: r.seq }, onclick: sel },
        time, h('span', { class: 'arrow' }, r.from === 'server' ? '←' : '→'),
        h('span', { class: 'what' }, h('span', { class: 'method' }, r.method ?? (r.type === 'orphan' ? 'response without a request' : 'not JSON-RPC'))),
        h('span', { class: 'chips' }, r.stopped ? chip('dropped', 'bad') : null), h('span', { class: 'lat' }));
    case 'event':
      return h('li', { class: `row event ev-${r.event.type}`, dataset: { seq: r.seq }, onclick: sel },
        time, h('span', { class: 'arrow' }, '◆'), h('span', { class: 'what' }, eventTitle(r.event)),
        h('span', { class: 'chips' }, eventChip(r.event)), h('span', { class: 'lat' }));
    case 'stderr':
      return h('li', { class: 'row stderr', dataset: { seq: r.seq }, onclick: sel },
        time, h('span', { class: 'arrow' }, '!'), h('span', { class: 'what' }, r.text), h('span', { class: 'chips' }), h('span', { class: 'lat' }));
    default:
      return h('li', { class: `row meta ${r.type}`, dataset: { seq: r.seq }, onclick: sel },
        time, h('span', { class: 'arrow' }, '·'), h('span', { class: 'what' }, metaTitle(r)), h('span', { class: 'chips' }), h('span', { class: 'lat' }));
  }
}

/** @param {string} text @param {string} tone */
function chip(text, tone) {
  return h('span', { class: `chip ${tone}` }, text);
}

/** @param {any} r */
function statusChip(r) {
  switch (r.status) {
    case 'blocked':
      return chip('blocked', 'bad');
    case 'error':
      return chip(r.resp?.error ? `error ${r.resp.error.code}` : 'tool error', 'warn');
    case 'pending':
      return chip('no reply', 'dim');
  }
  return chip('ok', 'ok');
}

/** @param {any} ev */
function eventChip(ev) {
  if (ev.action === 'block' || ev.action === 'drop') return chip('blocked', 'bad');
  if (ev.action === 'warn') return chip('warned', 'warn');
  return null;
}

/** @param {any} ev */
function eventTitle(ev) {
  switch (ev.type) {
    case 'drift':
      return [h('b', null, ev.tool), ' changed since it was pinned'];
    case 'suspicious':
      return [h('b', null, ev.tool), ': ', (ev.flags ?? []).map((/** @type {any} */ f) => f.rule).filter(uniq).join(', ')];
    case 'new_tool':
      return [h('b', null, ev.tool), ' is not in the lockfile'];
    case 'removed':
      return ['tools removed: ', (ev.tools ?? []).join(', ')];
    case 'repin':
      return ['re-pinned: ', (ev.tools ?? []).join(', ')];
    case 'malformed':
      return ['refused a malformed message: ', ev.reason];
    case 'deny':
      return [h('b', null, ev.tool), ' blocked: ', ev.reason];
    case 'redact':
      return ['redacted ', Object.values(ev.redactions ?? {}).reduce((a, b) => a + b, 0), ' secret(s)'];
  }
  return [ev.type];
}

/** @param {any} r */
function metaTitle(r) {
  switch (r.type) {
    case 'open':
      return `session opened by airlock ${r.rec.session?.airlock ?? ''}`;
    case 'close':
      return `server exited with status ${r.rec.exit}, ${r.rec.records} records${r.rec.sig ? ', signed' : ''}`;
    case 'checkpoint':
      return 'signed checkpoint';
  }
  return r.type;
}

const LEADING_ARGS = ['path', 'paths', 'source', 'destination', 'uri', 'url', 'city', 'region', 'query', 'pattern', 'name'];

/** @param {any} args */
function argSummary(args) {
  if (!args || typeof args !== 'object') return '';
  const rank = (/** @type {string} */ k) => (LEADING_ARGS.includes(k) ? LEADING_ARGS.indexOf(k) : LEADING_ARGS.length);
  const vals = Object.entries(args)
    .filter(([, v]) => typeof v === 'string' || typeof v === 'number')
    .sort(([a], [b]) => rank(a) - rank(b))
    .map(([k, v]) => (typeof v === 'string' && v.length > 48 ? `${k}=${v.slice(0, 45)}…` : `${k}=${v}`));
  return vals.slice(0, 2).join('  ');
}

// ---------------------------------------------------------------- detail

/**
 * The row a record belongs to: a call row covers its request, its response
 * and the events about it, so a link to any of those records lands on it.
 * @param {number|null} seq
 */
function rowFor(seq) {
  const rows = state.model.rows;
  return rows.find((/** @type {any} */ r) => r.seq === seq) ??
    rows.find((/** @type {any} */ r) => r.respSeq === seq || r.events?.some((/** @type {any} */ e) => e.seq === seq)) ??
    null;
}

/** @param {number|null} seq @param {boolean} [scroll] */
function select(seq, scroll) {
  const row = rowFor(seq);
  seq = row ? row.seq : null;
  state.selected = seq;
  markSelected(scroll);
  const pane = $('#detail');
  pane.replaceChildren(row ? detail(row) : h('p', { class: 'empty' }, 'Select a row.'));
  pane.scrollTop = 0;
  if (state.current) {
    const p = new URLSearchParams({ s: state.current.name });
    if (seq !== null) p.set('r', String(seq));
    history.replaceState(null, '', '#' + p.toString());
  }
}

/** @param {boolean} [scroll] */
function markSelected(scroll) {
  for (const li of document.querySelectorAll('#rows li')) {
    const on = Number(/** @type {HTMLElement} */ (li).dataset.seq) === state.selected;
    li.classList.toggle('sel', on);
    if (on && scroll) li.scrollIntoView({ block: 'center' });
  }
}

/** @param {any} r */
function detail(r) {
  switch (r.type) {
    case 'call':
      return callDetail(r);
    case 'event':
      return eventDetail(r.event);
    case 'stderr':
      return section('Server stderr', h('pre', { class: 'plain' }, r.text));
    case 'open':
      return section('Session', jsonView(r.rec.session));
    case 'close':
      return section('Session closed', jsonView({ exit: r.rec.exit, records: r.rec.records, signed: !!r.rec.sig, ts: r.rec.ts }));
    case 'checkpoint':
      return section('Signed checkpoint', jsonView({ seq: r.rec.seq, covers: r.rec.prev, sig: r.rec.sig }));
  }
  return section(r.stopped ? 'Dropped by airlock' : 'Message', r.msg !== undefined ? jsonView(r.msg) : h('pre', { class: 'plain' }, r.text ?? ''));
}

/** @param {any} r */
function callDetail(r) {
  const head = h('header', { class: 'dhead' },
    h('h2', null, r.tool ?? r.method, r.tool ? h('span', { class: 'm' }, r.method) : null),
    h('div', { class: 'chips' }, r.redacted ? chip('redacted', 'warn') : null, statusChip(r)));
  const facts = [
    ['id', JSON.stringify(r.id)],
    ['from', r.from],
    ['at', fmtOffset(r.t)],
    ['latency', r.latency === null ? '' : fmtMs(r.latency)],
  ];
  const d = r.decision;
  if (d) facts.push(['decision', d.type === 'allow' ? `allowed${d.rule ? ' by rule ' + d.rule : ' (default)'}` : `blocked by ${d.by}${d.rule ? ' (rule ' + d.rule + ')' : ''}`]);
  const out = [head, h('dl', { class: 'facts' }, facts.filter(([, v]) => v).map(([k, v]) => [h('dt', null, k), h('dd', null, v)]))];

  if (d?.type === 'deny') out.push(h('p', { class: 'reason bad' }, d.reason));
  for (const ev of r.events) {
    if (ev.type === 'redact') out.push(h('p', { class: 'reason warn' }, 'Redacted before the client saw it: ', Object.entries(ev.redactions).map(([k, n]) => `${n} × ${k}`).join(', ')));
    if (ev.type === 'malformed') out.push(h('p', { class: 'reason bad' }, ev.reason));
  }
  if (r.method === 'tools/list' && Array.isArray(r.resp?.result?.tools)) out.push(toolsTable(r));
  out.push(section(r.stopped ? 'Request (stopped by airlock)' : 'Request', jsonView(metaLast(r.req.params ?? {}))));
  if (r.resp) {
    const label = r.respFrom === 'airlock' ? 'Reply from airlock' : r.respFrom === 'client' ? 'Response from client' : 'Response from server';
    out.push(section(label, jsonView(metaLast(r.resp.result ?? { error: r.resp.error }))));
  }
  return h('div', null, out);
}

/** @param {any} r */
function toolsTable(r) {
  const flagged = new Map();
  for (const ev of r.events) {
    if (ev.tool && (ev.type === 'drift' || ev.type === 'suspicious' || ev.type === 'new_tool')) flagged.set(ev.tool, ev);
  }
  const drifted = r.events.filter((/** @type {any} */ e) => e.type === 'drift' && e.action === 'block').map((/** @type {any} */ e) => e.tool);
  const rows = r.resp.result.tools.map((/** @type {any} */ t) => {
    const ann = t.annotations ?? {};
    const hints = [ann.readOnlyHint && 'read-only', ann.destructiveHint && 'destructive', ann.openWorldHint && 'open world'].filter(Boolean);
    const ev = flagged.get(t.name);
    return h('tr', null, h('td', null, h('code', null, t.name)), h('td', null, t.title ?? ''), h('td', { class: 'dim' }, hints.join(', ')), h('td', null, ev ? eventChip(ev) ?? chip(ev.type, 'warn') : null));
  });
  const parts = [h('table', { class: 'tools' }, h('thead', null, h('tr', null, h('th', null, 'tool'), h('th', null, 'title'), h('th', null, 'hints'), h('th'))), h('tbody', null, rows))];
  if (drifted.length) parts.unshift(h('p', { class: 'reason bad' }, `Hidden from the client: ${drifted.join(', ')}. The list below is what the client received.`));
  const pins = r.events.find((/** @type {any} */ e) => e.type === 'pin');
  if (pins) parts.push(h('p', { class: 'dim' }, `First listing: pinned ${pins.tools.length} tool definition(s).`));
  return section(`Tools (${r.resp.result.tools.length})`, parts);
}

/** @param {any} ev */
function eventDetail(ev) {
  const out = [h('header', { class: 'dhead' }, h('h2', null, eventTitle(ev)), h('div', { class: 'chips' }, eventChip(ev)))];
  if (ev.reason) out.push(h('p', { class: 'reason' }, ev.reason));
  if (ev.flags?.length) {
    out.push(section('Heuristic flags',
      h('p', { class: 'dim' }, 'Pattern matches, not proof. They catch the published tool-poisoning tricks and miss careful ones.'),
      h('table', { class: 'flags' }, h('tbody', null, ev.flags.map((/** @type {any} */ f) =>
        h('tr', null, h('td', null, chip(f.severity, f.severity === 'high' ? 'bad' : 'dim')), h('td', null, h('code', null, f.rule)), h('td', { class: 'dim' }, f.where), h('td', null, strView(f.detail))))))));
  }
  if (ev.type === 'drift' && ev.old && ev.new) {
    out.push(h('dl', { class: 'facts' }, h('dt', null, 'pinned'), h('dd', null, h('code', null, ev.old_sha256?.slice(0, 16))), h('dt', null, 'now'), h('dd', null, h('code', null, ev.new_sha256?.slice(0, 16)))));
    if (ev.old.description !== ev.new.description) {
      out.push(section('Description, pinned → now', h('div', { class: 'wdiff' }, diff(words(ev.old.description ?? ''), words(ev.new.description ?? '')).map((p) => h('span', { class: p.op }, strView(p.text))))));
    }
    const a = JSON.stringify(ev.old, null, 2).split('\n');
    const b = JSON.stringify(ev.new, null, 2).split('\n');
    out.push(section('Definition, pinned → now', h('pre', { class: 'ldiff' }, diff(a, b).map((p) => h('div', { class: p.op }, h('span', { class: 'sign' }, p.op === 'ins' ? '+' : p.op === 'del' ? '−' : ' '), strView(p.text))))));
  } else if (ev.new) {
    out.push(section('Definition', jsonView(ev.new)));
  }
  out.push(section('Event', jsonView(ev)));
  return h('div', null, out);
}

/** Protocol metadata is rarely what you came for: list it last. @param {any} v */
function metaLast(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v) || !('_meta' in v)) return v;
  const { _meta, ...rest } = v;
  return { ...rest, _meta };
}

/** @param {string} title @param {...any} body */
function section(title, ...body) {
  return h('section', null, h('h3', null, title), body);
}

// ------------------------------------------------------------ JSON view

const MAX_STRING = 4000;

/** @param {any} v */
function jsonView(v) {
  const pre = h('pre', { class: 'json' });
  render(pre, v, 0);
  return pre;
}

/** @param {HTMLElement} out @param {any} v @param {number} depth */
function render(out, v, depth) {
  const pad = '  '.repeat(depth);
  if (v === null) return out.append(h('span', { class: 'j-null' }, 'null'));
  if (typeof v === 'string') return out.append(h('span', { class: 'j-str' }, '"', strView(v), '"'));
  if (typeof v === 'number') return out.append(h('span', { class: 'j-num' }, String(v)));
  if (typeof v === 'boolean') return out.append(h('span', { class: 'j-bool' }, String(v)));
  if (Array.isArray(v)) {
    if (!v.length) return out.append('[]');
    out.append('[\n');
    v.forEach((e, i) => {
      out.append(pad + '  ');
      render(out, e, depth + 1);
      out.append(i < v.length - 1 ? ',\n' : '\n');
    });
    return out.append(pad + ']');
  }
  const keys = Object.keys(v);
  if (!keys.length) return out.append('{}');
  out.append('{\n');
  keys.forEach((k, i) => {
    out.append(pad + '  ', h('span', { class: 'j-key' }, JSON.stringify(k)), ': ');
    render(out, v[k], depth + 1);
    out.append(i < keys.length - 1 ? ',\n' : '\n');
  });
  out.append(pad + '}');
}

/** Render a string with hidden characters made visible and redactions marked. @param {string} s */
function strView(s) {
  if (typeof s !== 'string') return String(s ?? '');
  let shown = s;
  let more = 0;
  if (shown.length > MAX_STRING) {
    more = shown.length - MAX_STRING;
    shown = shown.slice(0, MAX_STRING);
  }
  const frag = document.createDocumentFragment();
  for (const seg of revealHidden(shown)) {
    if (seg.hidden === 'tag') frag.append(h('span', { class: 'hid tag', title: 'Unicode tag characters: invisible in most interfaces, shown here decoded' }, seg.text));
    else if (seg.hidden === 'invisible') frag.append(h('span', { class: 'hid inv', title: 'invisible formatting characters' }, seg.text));
    else {
      const parts = seg.text.split(/(\[redacted:[a-z0-9-]+\])/);
      for (const p of parts) {
        if (!p) continue;
        frag.append(p.startsWith('[redacted:') ? h('span', { class: 'redacted' }, p) : document.createTextNode(p));
      }
    }
  }
  if (more) frag.append(h('span', { class: 'dim' }, ` … ${more.toLocaleString()} more characters`));
  return frag;
}

// ---------------------------------------------------------------- helpers

/** @param {number} ms */
function fmtOffset(ms) {
  if (!Number.isFinite(ms)) return '';
  const s = ms / 1000;
  if (s < 60) return '+' + s.toFixed(3);
  const m = Math.floor(s / 60);
  return `+${m}:${(s - m * 60).toFixed(3).padStart(6, '0')}`;
}

/** @param {number} ms */
function fmtMs(ms) {
  if (ms < 1) return '<1 ms';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(2)} s`;
}

/** @param {number} ms */
function fmtDuration(ms) {
  return ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;
}

/** @param {string} p */
function basename(p) {
  return p.split(/[/\\]/).pop() ?? p;
}

/** @param {any} v @param {number} i @param {any[]} a */
function uniq(v, i, a) {
  return a.indexOf(v) === i;
}

// ------------------------------------------------------------------ wiring

/** @param {FileList|File[]} files */
function addFiles(files) {
  const added = Array.from(files).map((f) => ({ name: f.name, file: f, note: 'local file' }));
  if (!added.length) return;
  state.sources = [...added, ...state.sources];
  load(added[0]);
}

function wire() {
  $('#session').addEventListener('change', (e) => load(state.sources[Number(/** @type {HTMLSelectElement} */ (e.target).value)]));
  $('#file').addEventListener('change', (e) => addFiles(/** @type {FileList} */ (/** @type {HTMLInputElement} */ (e.target).files)));
  for (const b of document.querySelectorAll('#filters button')) b.addEventListener('click', () => setFilter(/** @type {string} */ (/** @type {HTMLElement} */ (b).dataset.f)));
  $('#search').addEventListener('input', (e) => {
    state.query = /** @type {HTMLInputElement} */ (e.target).value.trim();
    renderList();
  });
  let depth = 0;
  window.addEventListener('dragenter', (e) => {
    e.preventDefault();
    depth++;
    document.body.classList.add('dropping');
  });
  window.addEventListener('dragleave', () => {
    if (--depth <= 0) document.body.classList.remove('dropping');
  });
  window.addEventListener('dragover', (e) => e.preventDefault());
  window.addEventListener('drop', (e) => {
    e.preventDefault();
    depth = 0;
    document.body.classList.remove('dropping');
    if (e.dataTransfer?.files) addFiles(e.dataTransfer.files);
  });
  window.addEventListener('keydown', (e) => {
    if (/** @type {HTMLElement} */ (e.target).tagName === 'INPUT') return;
    if (!['ArrowDown', 'ArrowUp', 'j', 'k'].includes(e.key)) return;
    e.preventDefault();
    const seqs = Array.from(document.querySelectorAll('#rows li'), (li) => Number(/** @type {HTMLElement} */ (li).dataset.seq));
    const i = seqs.indexOf(/** @type {number} */ (state.selected));
    const next = e.key === 'ArrowDown' || e.key === 'j' ? Math.min(seqs.length - 1, i + 1) : Math.max(0, i - 1);
    if (seqs.length) select(seqs[next], true);
  });
}

async function main() {
  wire();
  state.sources = await discover();
  $('#mode').textContent = state.remote ? 'local' : state.sources.length ? 'sample sessions' : '';
  const want = new URLSearchParams(location.hash.slice(1)).get('s');
  const src = state.sources.find((s) => s.name === want) ?? state.sources[0];
  if (src) load(src);
  else {
    renderPicker();
    $('#status').textContent = 'Drop a session log here, or use Open.';
  }
}

main();
