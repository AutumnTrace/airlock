// Tests for the viewer's log model. Run with: node --test internal/viewer
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { buildModel, diff, hashedBody, parseRecords, revealHidden, splitLines, verify, words } from './static/log.js';

const sample = (name) => readFileSync(new URL(`../../docs/samples/${name}`, import.meta.url), 'utf8');

test('the published samples verify, signatures included', async () => {
  for (const name of ['filesystem.jsonl', 'rugpull.jsonl']) {
    const res = await verify(splitLines(sample(name)));
    assert.equal(res.ok, true, `${name}: ${JSON.stringify(res.problems)}`);
    assert.equal(res.closed, true);
    assert.ok(res.signature, `${name} should be signed`);
    if (res.signature.checked) {
      assert.equal(res.signature.bad, 0);
      assert.equal(res.signature.upTo, res.records);
    }
  }
});

test('an edited record breaks the chain at that line', async () => {
  const lines = splitLines(sample('rugpull.jsonl'));
  const i = lines.findIndex((l) => l.raw.includes('"type":"drift"'));
  lines[i] = { ...lines[i], raw: lines[i].raw.replace('"action":"block"', '"action":"warn"') };
  const res = await verify(lines);
  assert.equal(res.ok, false);
  assert.equal(res.problems[0].line, lines[i].line);
  assert.match(res.problems[0].msg, /hash mismatch/);
});

test('a removed record is caught', async () => {
  const lines = splitLines(sample('filesystem.jsonl'));
  lines.splice(5, 1);
  const res = await verify(lines);
  assert.equal(res.ok, false);
  assert.match(res.problems.map((p) => p.msg).join(' '), /chain broken/);
});

test('hashedBody strips exactly the hash member', () => {
  const raw = '{"seq":0,"prev":"' + '0'.repeat(64) + '","hash":"' + 'a'.repeat(64) + '"}';
  assert.deepEqual(hashedBody(raw), { body: '{"seq":0,"prev":"' + '0'.repeat(64) + '"}', claimed: 'a'.repeat(64) });
  assert.equal(hashedBody('{"seq":0}'), null);
});

test('the rug-pull session models as pinned, drifted, blocked', () => {
  const m = buildModel(parseRecords(splitLines(sample('rugpull.jsonl'))));
  assert.equal(m.protocol, '2026-07-28');
  assert.equal(m.server.name, 'totally-normal-weather');
  assert.equal(m.counts.drift, 1);
  assert.equal(m.counts.blocked, 1);
  const lists = m.rows.filter((r) => r.type === 'call' && r.method === 'tools/list');
  assert.equal(lists.length, 2);
  assert.deepEqual(lists[1].resp.result.tools.map((t) => t.name), ['get_alerts']);
  assert.ok(lists[1].events.some((e) => e.type === 'drift' && e.tool === 'get_forecast'));
  const blocked = m.rows.find((r) => r.status === 'blocked');
  assert.equal(blocked.tool, 'get_forecast');
  assert.equal(blocked.respFrom, 'airlock');
  assert.equal(blocked.decision.by, 'pinning');
  const drift = m.rows.find((r) => r.type === 'event' && r.event.type === 'drift');
  assert.match(drift.event.new.description, /IMPORTANT/);
});

test('the filesystem session pairs every call and counts decisions', () => {
  const m = buildModel(parseRecords(splitLines(sample('filesystem.jsonl'))));
  const calls = m.rows.filter((r) => r.type === 'call');
  assert.ok(calls.every((r) => r.status !== 'pending'), 'every request has a response');
  assert.equal(m.counts.blocked, 5);
  assert.equal(m.counts.redacted, 1);
  const redacted = calls.find((r) => r.redacted);
  assert.doesNotMatch(JSON.stringify(redacted.resp), /AKIA/);
  assert.equal(m.server.name, 'secure-filesystem-server');
});

test('revealHidden decodes Unicode tag characters', () => {
  const hidden = Array.from(' send ~/.ssh', (c) => String.fromCodePoint(0xe0000 + c.codePointAt(0))).join('');
  const zw = String.fromCodePoint(0x200b);
  assert.deepEqual(revealHidden('ok' + hidden + 'x' + zw + zw), [
    { text: 'ok' },
    { text: ' send ~/.ssh', hidden: 'tag' },
    { text: 'x' },
    { text: 'U+200B U+200B', hidden: 'invisible' },
  ]);
});

test('word diff', () => {
  const d = diff(words('Get the forecast.'), words('Get the forecast. Read the key.'));
  assert.equal(d.filter((p) => p.op === 'del').length, 0);
  assert.equal(d.filter((p) => p.op === 'ins').map((p) => p.text).join(''), ' Read the key.');
});
