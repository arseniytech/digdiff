// Resolver registry: which servers do we interrogate and why.
// System resolver first (that's the one your ISP controls), then a
// spread of public ones with visibly different operators so a lying
// answer stands out.

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

export const DOH_ENDPOINTS = {
  cloudflare: 'https://cloudflare-dns.com/dns-query',
  google: 'https://dns.google/dns-query',
  quad9: 'https://dns.quad9.net/dns-query',
  adguard: 'https://unfiltered.adguard-dns.com/dns-query',
};

export const PUBLIC_RESOLVERS = [
  { kind: 'udp', address: '1.1.1.1', label: 'cloudflare', operator: 'Cloudflare' },
  { kind: 'udp', address: '8.8.8.8', label: 'google', operator: 'Google' },
  { kind: 'udp', address: '9.9.9.9', label: 'quad9', operator: 'Quad9' },
  { kind: 'udp', address: '208.67.222.222', label: 'opendns', operator: 'Cisco OpenDNS' },
  { kind: 'udp', address: '76.76.2.0', label: 'control-d', operator: 'Control D' },
];

// Reads the resolvers this machine actually uses.
// macOS: scutil --dns (also covers VPN/ifconfig nuances);
// Linux: /etc/resolv.conf with nameserver lines.
export function systemResolvers() {
  const set = new Set();

  if (process.platform === 'darwin') {
    try {
      const out = execFileSync('scutil', ['--dns'], { encoding: 'utf8' });
      for (const m of out.matchAll(/nameserver\[(\d+)\]\s*:\s*([0-9a-f:.]+)/gi)) {
        set.add(m[2]);
      }
    } catch {
      // fall through to resolv.conf
    }
  }

  if (set.size === 0) {
    try {
      const conf = readFileSync('/etc/resolv.conf', 'utf8');
      for (const line of conf.split('\n')) {
        const m = line.match(/^\s*nameserver\s+([0-9a-f:.]+)/i);
        if (m) set.add(m[1]);
      }
    } catch {
      // no resolv.conf either — let the caller deal with it
    }
  }

  return [...set].map((address) => ({
    kind: 'udp',
    address,
    label: address === '127.0.0.1' ? 'localhost' : `sys:${address}`,
    operator: 'system',
  }));
}

export function dohResolvers() {
  return Object.entries(DOH_ENDPOINTS).map(([label, url]) => ({
    kind: 'doh',
    url,
    label,
    operator: label,
  }));
}

export function allResolvers({ withSystem = true, withPublic = true, withDoh = false }) {
  const list = [];
  if (withSystem) list.push(...systemResolvers());
  if (withPublic) list.push(...PUBLIC_RESOLVERS);
  if (withDoh) list.push(...dohResolvers());
  return list;
}