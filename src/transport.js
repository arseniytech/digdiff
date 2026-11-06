// Transport layer: raw DNS over UDP (with TCP retry on truncation) and
// DNS-over-HTTPS (RFC 8484, wire format body — no JSON involved).

import dgram from 'node:dgram';
import net from 'node:net';
import https from 'node:https';
import { randomBytes } from 'node:crypto';

const UDP_TIMEOUT = 3000;
const TCP_TIMEOUT = 5000;

const makeId = () => randomBytes(2).readUInt16BE(0);

// Tries UDP first; on truncation flag retries over TCP using the same id.
export function queryUdp(server, buf, queryId) {
  return new Promise((resolve, reject) => {
    const id = queryId ?? makeId();
    const pkt = Buffer.from(buf);
    pkt.writeUInt16BE(id, 0);

    const socket = dgram.createSocket('udp4');
    const timer = setTimeout(() => {
      socket.close();
      reject(new Error('udp timeout'));
    }, UDP_TIMEOUT);

    socket.on('message', (msg) => {
      // only accept matching responses, keep listening until timeout
      if (msg.readUInt16BE(0) !== id) return;
      clearTimeout(timer);
      socket.close();
      const truncated = (msg.readUInt16BE(2) & 0x0200) !== 0;
      if (truncated) {
        queryTcp(server, pkt, id).then(resolve, reject);
      } else {
        resolve(msg);
      }
    });
    socket.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
    socket.send(pkt, 53, server, (err) => {
      if (err) {
        clearTimeout(timer);
        socket.close();
        reject(err);
      }
    });
  });
}

// DNS over TCP: 2-byte length prefix, then the packet.
export function queryTcp(server, pkt, queryId) {
  return new Promise((resolve, reject) => {
    const id = queryId ?? makeId();
    const buf = Buffer.from(pkt);
    buf.writeUInt16BE(id, 0);

    const socket = net.createConnection({ host: server, port: 53 });
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('tcp timeout'));
    }, TCP_TIMEOUT);

    const frame = Buffer.alloc(2 + buf.length);
    frame.writeUInt16BE(buf.length, 0);
    buf.copy(frame, 2);

    let response = Buffer.alloc(0);
    socket.on('connect', () => socket.write(frame));
    socket.on('data', (chunk) => {
      response = Buffer.concat([response, chunk]);
      if (response.length < 2) return;
      const len = response.readUInt16BE(0);
      if (response.length < 2 + len) return;
      clearTimeout(timer);
      socket.end();
      resolve(response.subarray(2, 2 + len));
    });
    socket.on('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

// DoH POST with the exact wire-format body. Some resolvers also accept GET,
// but POST is the spec-sanctioned one and keeps the payload binary-safe.
export function queryDoh(url, pkt, queryId) {
  return new Promise((resolve, reject) => {
    const id = queryId ?? makeId();
    const buf = Buffer.from(pkt);
    buf.writeUInt16BE(id, 0);

    const req = https.request(
      url,
      {
        method: 'POST',
        headers: {
          'content-type': 'application/dns-message',
          accept: 'application/dns-message',
          'content-length': buf.length,
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const body = Buffer.concat(chunks);
          if (res.statusCode !== 200) {
            reject(new Error(`doh http ${res.statusCode}`));
            return;
          }
          resolve(body);
        });
      }
    );
    req.setTimeout(UDP_TIMEOUT, () => req.destroy(new Error('doh timeout')));
    req.on('error', reject);
    req.end(buf);
  });
}

// Uniform entry point: everything takes a { kind, address, url } resolver.
export async function query(resolver, buf, id) {
  if (resolver.kind === 'udp') return queryUdp(resolver.address, buf, id);
  if (resolver.kind === 'doh') return queryDoh(resolver.url, buf, id);
  throw new Error(`unknown resolver kind: ${resolver.kind}`);
}