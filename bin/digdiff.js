#!/usr/bin/env node
// digdiff — ask a dozen resolvers the same question, watch them disagree.
//
//   digdiff example.com
//   digdiff example.com --type AAAA --dnssec --doh
//   digdiff example.com --json | jq .
//
// Exit codes: 0 = consensus, 1 = someone disagrees, 2 = jacked up.

import { parseArgs } from 'node:util';
import { TYPE } from '../src/dns.js';
import { allResolvers } from '../src/resolvers.js';
import { probeAll, judge, fetchGroundTruth, fingerprint, rcodeName } from '../src/probe.js';

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    type: { type: 'string', short: 't', default: 'A' },
    doh: { type: 'boolean', default: false },
    dnssec: { type: 'boolean', default: false },
    'no-system': { type: 'boolean', default: false },
    'no-public': { type: 'boolean', default: false },
    json: { type: 'boolean', default: false },
    nxdomain: { type: 'boolean', default: false },
    help: { type: 'boolean', short: 'h', default: false },
  },
});

if (values.help || positionals.length === 0) {
  console.log(`digdiff — compare DNS answers across resolvers

usage: digdiff <domain> [options]

options:
  -t, --type <A|AAAA|MX|TXT|NS|CNAME>  record type to ask for (default A)
      --doh                            also query DoH resolvers (encrypted)
      --dnssec                         set the DNSSEC DO bit and AD flag
      --no-system                      skip the machine's own resolvers
      --no-public                      skip public resolvers
      --nxdomain                       also probe a guaranteed-nonexistent
                                       name to catch NXDOMAIN hijacking
      --json                           machine-readable output
  -h, --help                           this text

exit codes: 0 consensus · 1 a resolver disagrees · 2 setup error`);
  process.exit(positionals.length === 0 ? 2 : 0);
}

const name = positionals[0];
const qtype = TYPE[String(values.type).toUpperCase()];
if (!qtype) {
  console.error(`unknown type: ${values.type}`);
  process.exit(2);
}

const resolvers = allResolvers({
  withSystem: !values['no-system'],
  withPublic: !values['no-public'],
  withDoh: values.doh,
});

if (resolvers.length === 0) {
  console.error('no resolvers to query — pass --doh or drop --no-* flags');
  process.exit(2);
}

const results = await probeAll(resolvers, name, qtype, { dnssec: values.dnssec });
// ground truth straight from the zone's own nameservers — the thing that
// actually decides what "the correct answer" is
const truth = await fetchGroundTruth(name, qtype);
const judged = judge(results, truth);
const disagree = judged.filter((j) => j.verdict === 'differ');
const failed = judged.filter((j) => j.verdict === 'error');

const TYPE_BY_VALUE = Object.fromEntries(Object.entries(TYPE).map(([k, v]) => [v, k]));

let extra = [];
if (values.nxdomain) {
  const bogus = `${Math.random().toString(36).slice(2)}.invalid`;
  const nx = judge(await probeAll(resolvers, bogus, TYPE.A, { dnssec: values.dnssec }));
  extra.push({ name: bogus, judged: nx });
  // NXDOMAIN hijackers return answers for a name that must not exist
  extra[0].hijacked = nx.some((j) => !j.result.error && j.result.rcode !== 3);
}

if (values.json) {
  console.log(JSON.stringify({
    name, type: String(values.type), consensus: disagree.length === 0,
    groundTruth: {
      error: truth.error,
      answers: fingerprint(truth.answers),
    },
    results: judged.map(({ result: r, verdict, majority }) => ({
      resolver: r.resolver.label,
      operator: r.resolver.operator,
      verdict,
      majority,
      rcode: r.rcode === null ? null : rcodeName(r.rcode),
      latencyMs: r.latencyMs,
      answers: fingerprint(r.answers),
      error: r.error ?? null,
    })),
    nxdomain: extra.map(({ name: n, judged: j, hijacked }) => ({
      name: n, hijacked,
      results: j.map(({ result: r, verdict: v }) => ({
        resolver: r.resolver.label, verdict: v,
        rcode: r.rcode === null ? null : rcodeName(r.rcode),
        answers: fingerprint(r.answers),
      })),
    })),
  }, null, 2));
} else {
  if (truth.answers.length) {
    console.log(`\nground truth (authoritative): ${fingerprint(truth.answers)}\n`);
  } else {
    console.log(`\n⚠ no authoritative answers (${truth.error}) — falling back to majority vote\n`);
  }
  printTable(name, qtype, judged);
  if (extra.length) {
    for (const { name: n, judged: j, hijacked } of extra) {
      console.log(`\nNXDOMAIN probe ${n} (must not exist)`);
      printTable(n, TYPE.A, j);
      if (hijacked) console.log('\nWARNING: a resolver answered for a nonexistent name — NXDOMAIN hijacking!');
    }
  }
  const lines = [];
  if (disagree.length) lines.push(`✗ ${disagree.length} resolver(s) disagree with the majority`);
  if (failed.length) lines.push(`✗ ${failed.length} resolver(s) failed to respond`);
  if (extra.some((e) => e.hijacked)) lines.push('✗ NXDOMAIN hijacking detected');
  if (!lines.length) lines.push('✓ all resolvers agree');
  console.log(`\n${lines.join('\n')}`);
}

process.exit(disagree.length || failed.length ? 1 : 0);

function printTable(name, qtype, judged) {
  const rows = judged.map(({ result: r, verdict, majority }) => [
    r.resolver.label,
    r.resolver.operator,
    verdict,
    r.error ?? (r.rcode === null ? '-' : rcodeName(r.rcode)),
    r.latencyMs === null ? '–' : `${r.latencyMs}ms`,
    fingerprint(r.answers) ?? '—',
    verdict === 'differ' ? `≠ ${majority}` : '',
  ]);
  const widths = [0, 0, 0, 0, 0, 0, 0];
  for (const row of [...rows, ['resolver', 'operator', 'verdict', 'rcode', 'latency', 'answers', '']]) {
    row.forEach((cell, i) => (widths[i] = Math.max(widths[i], cell.length)));
  }

  const fmt = (row) =>
    row.map((cell, i) => cell.padEnd(widths[i])).join('  ').trimEnd();

  console.log(`\n${name}  ${TYPE_BY_VALUE[qtype] ?? qtype}`);
  console.log(fmt(['resolver', 'operator', 'verdict', 'rcode', 'latency', 'answers', '']));
  console.log(fmt(widths.map((w) => '-'.repeat(w))));
  for (const row of rows) console.log(fmt(row));
}