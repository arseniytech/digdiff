// DNS wire format, implemented from the RFC 1035 ground up.
// No deps, no lookup tables borrowed from anywhere — just buffers.

export const TYPE = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  OPT: 41,
};

export const CLASS_IN = 1;

// Builds a query payload: header + question + optional EDNS0 OPT record.
// opts.dnssec adds the DO bit so resolvers send us RRSIG/records.
export function buildQuery(id, name, qtype, opts = {}) {
  const question = encodeName(name, []);
  const qdcount = 1;

  // OPT record: root label (1 byte), type, class=payload size,
  // ttl=flags (DO bit 0x8000), rdlen=0. Always 11 bytes.
  let opt = Buffer.alloc(0);
  if (opts.edns) {
    opt = Buffer.alloc(11);
    opt[0] = 0x00; // root name
    opt.writeUInt16BE(TYPE.OPT, 1);
    opt.writeUInt16BE(4096, 3); // UDP payload size we accept
    if (opts.dnssec) opt.writeUInt16BE(0x8000, 5); // DO bit in ttl-flags
    opt.writeUInt16BE(0, 9); // RDLENGTH
  }

  const buf = Buffer.alloc(12 + question.length + 4 + opt.length);
  buf.writeUInt16BE(id, 0);
  // flags: RD (0x0100) always set, AD (0x0020) when dnssec
  buf.writeUInt16BE(0x0100 | (opts.dnssec ? 0x0020 : 0), 2);
  buf.writeUInt16BE(qdcount, 4);
  buf.writeUInt16BE(0, 6); // ancount
  buf.writeUInt16BE(0, 8); // nscount
  buf.writeUInt16BE(opts.edns ? 1 : 0, 10); // arcount
  question.copy(buf, 12);
  buf.writeUInt16BE(qtype, 12 + question.length);
  buf.writeUInt16BE(CLASS_IN, 14 + question.length);
  opt.copy(buf, 16 + question.length);
  return buf;
}

// Encodes a domain name as a sequence of length-prefixed labels.
// labels: ['www', 'google', 'com'] -> 03www06google03com00
// The offsets array is used for compression on the encode side — we keep
// it for symmetry with decode; compression on write is rarely worth it for
// single-question queries, but the decoder MUST handle pointers.
export function encodeName(name, offsets) {
  const labels = name.split('.');
  const parts = [];
  for (const label of labels) {
    if (!label) continue;
    const bytes = Buffer.from(label, 'ascii');
    if (bytes.length > 63) throw new Error(`label too long: ${label}`);
    parts.push(Buffer.from([bytes.length]), bytes);
  }
  return Buffer.concat([...parts, Buffer.from([0])]);
}

const MAX_POINTER_JUMPS = 128; // guards against pointer loops

// Decodes a possibly-compressed name starting at offset.
// Returns { name, end } where end is the position right after the name in
// the packet (for compressed names that's not the jump target).
export function decodeName(buf, offset) {
  const labels = [];
  let pos = offset;
  let end = null;
  let jumps = 0;

  while (true) {
    if (pos >= buf.length) throw new Error('name runs past packet end');
    const len = buf[pos];

    if ((len & 0xc0) === 0xc0) {
      // compression pointer to a name elsewhere in the packet
      if (pos + 1 >= buf.length) throw new Error('truncated pointer');
      const target = ((len & 0x3f) << 8) | buf[pos + 1];
      if (end === null) end = pos + 2;
      if (++jumps > MAX_POINTER_JUMPS) throw new Error('pointer loop detected');
      pos = target;
      continue;
    }

    if (len === 0) {
      if (end === null) end = pos + 1;
      break;
    }

    if (len > 63) throw new Error('invalid label length');
    labels.push(buf.toString('ascii', pos + 1, pos + 1 + len));
    pos += 1 + len;
  }

  return { name: labels.join('.'), end };
}

// Parses a full response into a plain object we can diff around.
export function parseResponse(buf) {
  if (buf.length < 12) throw new Error('packet too short');

  const id = buf.readUInt16BE(0);
  const flags = buf.readUInt16BE(2);
  const qdcount = buf.readUInt16BE(4);
  const ancount = buf.readUInt16BE(6);
  const nscount = buf.readUInt16BE(8);
  const arcount = buf.readUInt16BE(10);

  let pos = 12;
  const questions = [];
  for (let i = 0; i < qdcount; i++) {
    const { name, end } = decodeName(buf, pos);
    const qtype = buf.readUInt16BE(end);
    const qclass = buf.readUInt16BE(end + 2);
    questions.push({ name, qtype, qclass });
    pos = end + 4;
  }

  const answers = [];
  for (let i = 0; i < ancount + nscount + arcount; i++) {
    const { name, end } = decodeName(buf, pos);
    const rtype = buf.readUInt16BE(end);
    const rclass = buf.readUInt16BE(end + 2);
    const ttl = buf.readUInt32BE(end + 4);
    const rdlength = buf.readUInt16BE(end + 8);
    const rdataStart = end + 10;
    const rdataEnd = rdataStart + rdlength;
    if (rdataEnd > buf.length) throw new Error('rdata runs past packet end');

    answers.push({
      name,
      type: rtype,
      class: rclass,
      ttl,
      data: decodeRdata(buf, rtype, rdataStart, rdataEnd),
      section: i < ancount ? 'answer' : i < ancount + nscount ? 'authority' : 'additional',
    });
    pos = rdataEnd;
  }

  return {
    id,
    flags,
    rcode: flags & 0x0f,
    truncated: (flags & 0x0200) !== 0,
    authoritative: (flags & 0x0400) !== 0,
    authenticated: (flags & 0x0020) !== 0,
    questions,
    answers,
  };
}

function decodeRdata(buf, rtype, start, end) {
  const slice = () => buf.subarray(start, end);

  switch (rtype) {
    case TYPE.A:
      return { ipv4: [...slice()].join('.') };
    case TYPE.AAAA: {
      const parts = [];
      for (let i = 0; i < 16; i += 2) {
        const word = buf.readUInt16BE(start + i);
        parts.push(word.toString(16));
      }
      return { ipv6: parts.join(':') };
    }
    case TYPE.CNAME:
    case TYPE.NS:
    case TYPE.PTR: {
      const { name } = decodeName(buf, start);
      return { target: name };
    }
    case TYPE.MX: {
      const pref = buf.readUInt16BE(start);
      const { name } = decodeName(buf, start + 2);
      return { preference: pref, exchange: name };
    }
    case TYPE.SOA: {
      const { name: mname, end: mnameEnd } = decodeName(buf, start);
      const { name: rname, end: rnameEnd } = decodeName(buf, mnameEnd);
      return {
        mname,
        rname,
        serial: buf.readUInt32BE(rnameEnd),
        refresh: buf.readUInt32BE(rnameEnd + 4),
        retry: buf.readUInt32BE(rnameEnd + 8),
        expire: buf.readUInt32BE(rnameEnd + 12),
        minimum: buf.readUInt32BE(rnameEnd + 16),
      };
    }
    case TYPE.TXT: {
      const strings = [];
      let pos = start;
      while (pos < end) {
        const len = buf[pos];
        strings.push(buf.toString('utf8', pos + 1, pos + 1 + len));
        pos += 1 + len;
      }
      return { strings };
    }
    case TYPE.SRV: {
      const priority = buf.readUInt16BE(start);
      const weight = buf.readUInt16BE(start + 2);
      const port = buf.readUInt16BE(start + 4);
      const { name } = decodeName(buf, start + 6);
      return { priority, weight, port, target: name };
    }
    case TYPE.OPT:
      // zero-length rdata; the interesting bits (payload size, flags) live
      // in the header fields class/ttl, not in the rdata
      return {};
    default:
      return { raw: slice().toString('hex') };
  }
}

// Human-readable glue for the type codes we understand.
export function typeName(t) {
  const entry = Object.entries(TYPE).find(([, v]) => v === t);
  return entry ? entry[0] : String(t);
}