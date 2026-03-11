/**
 * MP4/MOV Binary Container Parser
 *
 * Parses ISO Base Media File Format (ISO 14496-12) containers directly
 * from an ArrayBuffer. Extracts metadata, sample tables, and structural
 * information needed for forensic analysis without any server or ffprobe.
 */

const CONTAINER_TYPES = new Set([
  'moov','trak','mdia','minf','stbl','udta','edts','dinf',
  'mvex','moof','traf','mfra','sinf','schi','rinf','strk',
]);

const META_CONTAINER = new Set(['meta']);

function readStr(dv, offset, len) {
  let s = '';
  for (let i = 0; i < len; i++) s += String.fromCharCode(dv.getUint8(offset + i));
  return s;
}

function macEpochToDate(seconds) {
  if (!seconds || seconds < 0) return null;
  const MAC_EPOCH_OFFSET = 2082844800;
  const unixSec = seconds - MAC_EPOCH_OFFSET;
  if (unixSec < 0 || unixSec > 4102444800) return null;
  return new Date(unixSec * 1000);
}

function parseBoxHeader(dv, offset) {
  if (offset + 8 > dv.byteLength) return null;
  let size = dv.getUint32(offset);
  const type = readStr(dv, offset + 4, 4);
  let headerSize = 8;
  if (size === 1) {
    if (offset + 16 > dv.byteLength) return null;
    const hi = dv.getUint32(offset + 8);
    const lo = dv.getUint32(offset + 12);
    size = hi * 0x100000000 + lo;
    headerSize = 16;
  } else if (size === 0) {
    size = dv.byteLength - offset;
  }
  return { size, type, headerSize, offset };
}

function parseFtyp(dv, offset, size) {
  const end = offset + size;
  if (offset + 8 > end) return {};
  const majorBrand = readStr(dv, offset, 4);
  const minorVersion = dv.getUint32(offset + 4);
  const compatibleBrands = [];
  for (let p = offset + 8; p + 4 <= end; p += 4) {
    compatibleBrands.push(readStr(dv, p, 4));
  }
  return { majorBrand, minorVersion, compatibleBrands };
}

function parseMvhd(dv, offset, size) {
  if (size < 4) return {};
  const version = dv.getUint8(offset);
  let timescale, duration, creationTime, modificationTime;
  if (version === 1) {
    if (size < 32) return {};
    const ctHi = dv.getUint32(offset + 4);
    const ctLo = dv.getUint32(offset + 8);
    creationTime = ctHi * 0x100000000 + ctLo;
    const mtHi = dv.getUint32(offset + 12);
    const mtLo = dv.getUint32(offset + 16);
    modificationTime = mtHi * 0x100000000 + mtLo;
    timescale = dv.getUint32(offset + 20);
    const dHi = dv.getUint32(offset + 24);
    const dLo = dv.getUint32(offset + 28);
    duration = dHi * 0x100000000 + dLo;
  } else {
    if (size < 20) return {};
    creationTime = dv.getUint32(offset + 4);
    modificationTime = dv.getUint32(offset + 8);
    timescale = dv.getUint32(offset + 12);
    duration = dv.getUint32(offset + 16);
  }
  return {
    version,
    timescale,
    durationUnits: duration,
    durationSeconds: timescale > 0 ? duration / timescale : 0,
    creationTime: macEpochToDate(creationTime),
    modificationTime: macEpochToDate(modificationTime),
  };
}

function parseTkhd(dv, offset, size) {
  if (size < 4) return {};
  const version = dv.getUint8(offset);
  let trackId, duration, creationTime, modificationTime;
  let widthOff;
  if (version === 1) {
    if (size < 88) return {};
    const ctHi = dv.getUint32(offset + 4);
    const ctLo = dv.getUint32(offset + 8);
    creationTime = ctHi * 0x100000000 + ctLo;
    const mtHi = dv.getUint32(offset + 12);
    const mtLo = dv.getUint32(offset + 16);
    modificationTime = mtHi * 0x100000000 + mtLo;
    trackId = dv.getUint32(offset + 20);
    const dHi = dv.getUint32(offset + 28);
    const dLo = dv.getUint32(offset + 32);
    duration = dHi * 0x100000000 + dLo;
    widthOff = offset + 76;
  } else {
    if (size < 80) return {};
    creationTime = dv.getUint32(offset + 4);
    modificationTime = dv.getUint32(offset + 8);
    trackId = dv.getUint32(offset + 12);
    duration = dv.getUint32(offset + 20);
    widthOff = offset + 68;
  }
  const width = dv.getUint16(widthOff) + dv.getUint16(widthOff + 2) / 65536;
  const height = dv.getUint16(widthOff + 4) + dv.getUint16(widthOff + 6) / 65536;
  return {
    version, trackId, duration,
    creationTime: macEpochToDate(creationTime),
    modificationTime: macEpochToDate(modificationTime),
    width: Math.round(width), height: Math.round(height),
  };
}

function parseMdhd(dv, offset, size) {
  if (size < 4) return {};
  const version = dv.getUint8(offset);
  let timescale, duration, creationTime, modificationTime, langCode;
  if (version === 1) {
    if (size < 32) return {};
    const ctHi = dv.getUint32(offset + 4);
    const ctLo = dv.getUint32(offset + 8);
    creationTime = ctHi * 0x100000000 + ctLo;
    const mtHi = dv.getUint32(offset + 12);
    const mtLo = dv.getUint32(offset + 16);
    modificationTime = mtHi * 0x100000000 + mtLo;
    timescale = dv.getUint32(offset + 20);
    const dHi = dv.getUint32(offset + 24);
    const dLo = dv.getUint32(offset + 28);
    duration = dHi * 0x100000000 + dLo;
    langCode = dv.getUint16(offset + 32);
  } else {
    if (size < 20) return {};
    creationTime = dv.getUint32(offset + 4);
    modificationTime = dv.getUint32(offset + 8);
    timescale = dv.getUint32(offset + 12);
    duration = dv.getUint32(offset + 16);
    langCode = dv.getUint16(offset + 20);
  }
  let language = '';
  if (langCode && langCode < 0x800) {
    language = String.fromCharCode(
      ((langCode >> 10) & 0x1f) + 0x60,
      ((langCode >> 5) & 0x1f) + 0x60,
      (langCode & 0x1f) + 0x60,
    );
  }
  return {
    version, timescale,
    durationUnits: duration,
    durationSeconds: timescale > 0 ? duration / timescale : 0,
    creationTime: macEpochToDate(creationTime),
    modificationTime: macEpochToDate(modificationTime),
    language,
  };
}

function parseHdlr(dv, offset, size) {
  if (size < 12) return {};
  const handlerType = readStr(dv, offset + 8, 4);
  let name = '';
  if (size > 24) {
    const nameLen = Math.min(size - 24, 256);
    name = readStr(dv, offset + 24, nameLen).replace(/\0+$/, '');
  }
  return { handlerType, name };
}

function parseStts(dv, offset, size) {
  if (size < 8) return { entries: [] };
  const entryCount = dv.getUint32(offset + 4);
  const entries = [];
  const maxEntries = Math.min(entryCount, 50000);
  for (let i = 0; i < maxEntries; i++) {
    const p = offset + 8 + i * 8;
    if (p + 8 > offset + size) break;
    entries.push({
      sampleCount: dv.getUint32(p),
      sampleDelta: dv.getUint32(p + 4),
    });
  }
  return { entryCount, entries };
}

function parseStss(dv, offset, size) {
  if (size < 8) return { entries: [] };
  const entryCount = dv.getUint32(offset + 4);
  const entries = [];
  const maxEntries = Math.min(entryCount, 50000);
  for (let i = 0; i < maxEntries; i++) {
    const p = offset + 8 + i * 4;
    if (p + 4 > offset + size) break;
    entries.push(dv.getUint32(p));
  }
  return { entryCount, entries };
}

function parseCtts(dv, offset, size) {
  if (size < 8) return { entries: [] };
  const version = dv.getUint8(offset);
  const entryCount = dv.getUint32(offset + 4);
  const entries = [];
  const maxEntries = Math.min(entryCount, 50000);
  for (let i = 0; i < maxEntries; i++) {
    const p = offset + 8 + i * 8;
    if (p + 8 > offset + size) break;
    entries.push({
      sampleCount: dv.getUint32(p),
      sampleOffset: version === 1 ? dv.getInt32(p + 4) : dv.getUint32(p + 4),
    });
  }
  return { version, entryCount, entries };
}

function parseStsz(dv, offset, size) {
  if (size < 12) return { sampleSize: 0, sampleCount: 0, entries: [] };
  const sampleSize = dv.getUint32(offset + 4);
  const sampleCount = dv.getUint32(offset + 8);
  const entries = [];
  if (sampleSize === 0) {
    const maxEntries = Math.min(sampleCount, 100000);
    for (let i = 0; i < maxEntries; i++) {
      const p = offset + 12 + i * 4;
      if (p + 4 > offset + size) break;
      entries.push(dv.getUint32(p));
    }
  }
  return { sampleSize, sampleCount, entries };
}

function parseStsc(dv, offset, size) {
  if (size < 8) return { entries: [] };
  const entryCount = dv.getUint32(offset + 4);
  const entries = [];
  const maxEntries = Math.min(entryCount, 50000);
  for (let i = 0; i < maxEntries; i++) {
    const p = offset + 8 + i * 12;
    if (p + 12 > offset + size) break;
    entries.push({
      firstChunk: dv.getUint32(p),
      samplesPerChunk: dv.getUint32(p + 4),
      sampleDescriptionIndex: dv.getUint32(p + 8),
    });
  }
  return { entryCount, entries };
}

function parseElst(dv, offset, size) {
  if (size < 8) return { entries: [] };
  const version = dv.getUint8(offset);
  const entryCount = dv.getUint32(offset + 4);
  const entries = [];
  const maxEntries = Math.min(entryCount, 1000);
  const entrySize = version === 1 ? 20 : 12;
  for (let i = 0; i < maxEntries; i++) {
    const p = offset + 8 + i * entrySize;
    if (p + entrySize > offset + size) break;
    if (version === 1) {
      const dHi = dv.getUint32(p);
      const dLo = dv.getUint32(p + 4);
      const mtHi = dv.getInt32(p + 8);
      const mtLo = dv.getUint32(p + 12);
      entries.push({
        segmentDuration: dHi * 0x100000000 + dLo,
        mediaTime: mtHi * 0x100000000 + mtLo,
        mediaRateInteger: dv.getInt16(p + 16),
        mediaRateFraction: dv.getInt16(p + 18),
      });
    } else {
      entries.push({
        segmentDuration: dv.getUint32(p),
        mediaTime: dv.getInt32(p + 4),
        mediaRateInteger: dv.getInt16(p + 8),
        mediaRateFraction: dv.getInt16(p + 10),
      });
    }
  }
  return { version, entryCount, entries };
}

function parseStsd(dv, offset, size) {
  if (size < 8) return { entryCount: 0, entries: [] };
  const entryCount = dv.getUint32(offset + 4);
  const entries = [];
  let p = offset + 8;
  const end = offset + size;
  for (let i = 0; i < Math.min(entryCount, 8); i++) {
    if (p + 8 > end) break;
    const eSize = dv.getUint32(p);
    const format = readStr(dv, p + 4, 4);
    entries.push({ format, size: eSize });
    p += Math.max(8, eSize);
  }
  return { entryCount, entries };
}

function tryParseUdtaStrings(dv, offset, size) {
  const tags = {};
  let p = offset;
  const end = offset + size;
  while (p + 8 <= end) {
    const boxSize = dv.getUint32(p);
    if (boxSize < 8 || p + boxSize > end) break;
    const boxType = readStr(dv, p + 4, 4);
    if (boxType.charCodeAt(0) === 0xa9 || boxType === 'name') {
      const strLen = Math.min(boxSize - 8, 512);
      if (strLen > 0) {
        let innerOff = p + 8;
        let str = '';
        if (innerOff + 4 <= p + boxSize) {
          const possibleDataSize = dv.getUint32(innerOff);
          if (possibleDataSize > 0 && possibleDataSize <= boxSize - 8 && innerOff + 8 <= p + boxSize) {
            const readLen = Math.min(possibleDataSize - 8, 512);
            if (readLen > 0) str = readStr(dv, innerOff + 8, readLen);
          } else {
            str = readStr(dv, innerOff, strLen);
          }
        }
        str = str.replace(/[\x00-\x1f]/g, '').trim();
        if (str) {
          const key = boxType.replace(/^\xa9/, '');
          tags[key] = str;
        }
      }
    }
    p += boxSize;
  }
  return tags;
}

function parseBoxTree(dv, start, end, depth = 0) {
  const boxes = [];
  let offset = start;
  const maxDepth = 8;

  while (offset < end) {
    const hdr = parseBoxHeader(dv, offset);
    if (!hdr || hdr.size < 8 || offset + hdr.size > end + 4) break;

    const boxEnd = Math.min(offset + hdr.size, end);
    const dataOffset = offset + hdr.headerSize;
    const dataSize = boxEnd - dataOffset;
    const box = { type: hdr.type, offset: hdr.offset, size: hdr.size, data: {} };

    if (META_CONTAINER.has(hdr.type) && dataSize >= 4) {
      const possibleVersion = dv.getUint8(dataOffset);
      const childStart = possibleVersion === 0 ? dataOffset + 4 : dataOffset;
      if (depth < maxDepth) {
        box.children = parseBoxTree(dv, childStart, boxEnd, depth + 1);
      }
    } else if (CONTAINER_TYPES.has(hdr.type) && depth < maxDepth) {
      box.children = parseBoxTree(dv, dataOffset, boxEnd, depth + 1);
    }

    try {
      switch (hdr.type) {
        case 'ftyp': box.data = parseFtyp(dv, dataOffset, dataSize); break;
        case 'mvhd': box.data = parseMvhd(dv, dataOffset, dataSize); break;
        case 'tkhd': box.data = parseTkhd(dv, dataOffset, dataSize); break;
        case 'mdhd': box.data = parseMdhd(dv, dataOffset, dataSize); break;
        case 'hdlr': box.data = parseHdlr(dv, dataOffset, dataSize); break;
        case 'stts': box.data = parseStts(dv, dataOffset, dataSize); break;
        case 'stss': box.data = parseStss(dv, dataOffset, dataSize); break;
        case 'ctts': box.data = parseCtts(dv, dataOffset, dataSize); break;
        case 'stsz': box.data = parseStsz(dv, dataOffset, dataSize); break;
        case 'stsc': box.data = parseStsc(dv, dataOffset, dataSize); break;
        case 'elst': box.data = parseElst(dv, dataOffset, dataSize); break;
        case 'stsd': box.data = parseStsd(dv, dataOffset, dataSize); break;
        case 'udta':
          box.data = tryParseUdtaStrings(dv, dataOffset, dataSize);
          break;
      }
    } catch (_) { /* Graceful fallback on malformed boxes */ }

    boxes.push(box);
    offset = boxEnd;
  }
  return boxes;
}

function findBox(boxes, type) {
  for (const box of boxes) {
    if (box.type === type) return box;
    if (box.children) {
      const found = findBox(box.children, type);
      if (found) return found;
    }
  }
  return null;
}

function findAllBoxes(boxes, type) {
  const result = [];
  for (const box of boxes) {
    if (box.type === type) result.push(box);
    if (box.children) result.push(...findAllBoxes(box.children, type));
  }
  return result;
}

function extractTracks(boxes) {
  const traks = findAllBoxes(boxes, 'trak');
  return traks.map(trak => {
    const tkhd = findBox(trak.children || [], 'tkhd');
    const mdhd = findBox(trak.children || [], 'mdhd');
    const hdlr = findBox(trak.children || [], 'hdlr');
    const stts = findBox(trak.children || [], 'stts');
    const stss = findBox(trak.children || [], 'stss');
    const ctts = findBox(trak.children || [], 'ctts');
    const stsz = findBox(trak.children || [], 'stsz');
    const stsc = findBox(trak.children || [], 'stsc');
    const elst = findBox(trak.children || [], 'elst');
    const stsd = findBox(trak.children || [], 'stsd');
    return {
      tkhd: tkhd?.data || {},
      mdhd: mdhd?.data || {},
      hdlr: hdlr?.data || {},
      stts: stts?.data || { entries: [] },
      stss: stss?.data || null,
      ctts: ctts?.data || null,
      stsz: stsz?.data || { sampleSize: 0, sampleCount: 0, entries: [] },
      stsc: stsc?.data || { entries: [] },
      elst: elst?.data || null,
      stsd: stsd?.data || null,
      type: hdlr?.data?.handlerType || 'unknown',
    };
  });
}

function collectAllTags(boxes) {
  const tags = {};
  const udtaBoxes = findAllBoxes(boxes, 'udta');
  for (const u of udtaBoxes) {
    if (u.data && typeof u.data === 'object') Object.assign(tags, u.data);
  }
  return tags;
}

function getTopLevelLayout(boxes) {
  return boxes.map(b => ({ type: b.type, offset: b.offset, size: b.size }));
}

export function parseMP4(buffer) {
  const dv = new DataView(buffer);
  const boxes = parseBoxTree(dv, 0, buffer.byteLength);

  const ftyp = findBox(boxes, 'ftyp');
  const mvhd = findBox(boxes, 'mvhd');
  const tracks = extractTracks(boxes);
  const tags = collectAllTags(boxes);
  const layout = getTopLevelLayout(boxes);

  const videoTrack = tracks.find(t => t.type === 'vide') || null;
  const audioTrack = tracks.find(t => t.type === 'soun') || null;

  const moovBox = findBox(boxes, 'moov');
  const mdatBox = findBox(boxes, 'mdat');
  const moovBeforeMdat = moovBox && mdatBox ? moovBox.offset < mdatBox.offset : null;

  return {
    ftyp: ftyp?.data || {},
    mvhd: mvhd?.data || {},
    tracks,
    videoTrack,
    audioTrack,
    tags,
    layout,
    moovBeforeMdat,
    fileSize: buffer.byteLength,
    boxes,
  };
}

export async function computeSHA256(buffer) {
  const hash = await crypto.subtle.digest('SHA-256', buffer);
  return Array.from(new Uint8Array(hash))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}
