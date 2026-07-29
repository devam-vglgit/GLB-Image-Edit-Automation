// ─────────────────────────────────────────────────────────────
// Square crop/pad — 1:1 output, product+shadow ≈80%, background ≈20%
//
// Deterministic (not prompt-guided): detects the bounding box of everything
// that ISN'T pure-white background (i.e. the product AND its shadow together),
// then composes a square canvas sized so that bounding box occupies ~80% of
// the frame — cropping away excess white margin if the model left too much,
// or padding with white if the model framed too tight. The product/shadow
// bounding box is NEVER cropped into; only background is added or removed.
//
// Any failure returns the original image unchanged. Disable with SQUARE_PAD=off.
// Tune via env: SQUARE_FILL (default 0.80 — content's share of the frame).
// ─────────────────────────────────────────────────────────────
const Jimp = require('jimp');

async function padToSquare(dataUrl) {
  if (process.env.SQUARE_PAD === 'off') return dataUrl;
  try {
    const m = /^data:(.*?);base64,(.*)$/.exec(dataUrl || '');
    if (!m) return dataUrl;
    const img = await Jimp.read(Buffer.from(m[2], 'base64'));
    const w = img.bitmap.width, h = img.bitmap.height, data = img.bitmap.data;

    // Background = near-pure #FFFFFF (tight tolerance, JPEG noise only). Anything
    // even slightly off-white — cream/pink pearls, ivory metal, pale gemstones,
    // grey shadow — counts as CONTENT to preserve. A loose threshold here was
    // misreading pale pearls/pastel stones as background, shrinking the detected
    // bounding box and cutting off part of the piece (e.g. the top of a chain).
    const isBackground = (i) => {
      const r = data[i], g = data[i + 1], b = data[i + 2];
      return r >= 250 && g >= 250 && b >= 250 && (Math.max(r, g, b) - Math.min(r, g, b)) <= 4;
    };

    let minX = w, minY = h, maxX = -1, maxY = -1;
    for (let y = 0; y < h; y++) {
      const rowBase = y * w * 4;
      for (let x = 0; x < w; x++) {
        if (!isBackground(rowBase + x * 4)) {
          if (x < minX) minX = x; if (x > maxX) maxX = x;
          if (y < minY) minY = y; if (y > maxY) maxY = y;
        }
      }
    }
    if (maxX < 0) return dataUrl;   // all-white / nothing detected — leave as-is

    const FILL = Number(process.env.SQUARE_FILL) || 0.80;
    const contentW = maxX - minX + 1, contentH = maxY - minY + 1;
    const cx = (minX + maxX + 1) / 2, cy = (minY + maxY + 1) / 2;

    // Square side such that the content's longer dimension is exactly FILL of it.
    const side = Math.round(Math.max(contentW, contentH) / FILL);

    const left = Math.round(cx - side / 2);
    const top = Math.round(cy - side / 2);

    const canvas = new Jimp(side, side, 0xFFFFFFFF);
    // Composite only the overlapping region between the source image and the
    // new square window — this crops excess background OR pads with white,
    // in one step, without ever touching pixels inside the content bbox.
    const srcX = Math.max(0, left), srcY = Math.max(0, top);
    const dstX = Math.max(0, -left), dstY = Math.max(0, -top);
    const copyW = Math.min(w - srcX, side - dstX);
    const copyH = Math.min(h - srcY, side - dstY);
    if (copyW > 0 && copyH > 0) {
      const region = img.clone().crop(srcX, srcY, copyW, copyH);
      canvas.composite(region, dstX, dstY);
    }

    const outBuf = await canvas.getBufferAsync(Jimp.MIME_PNG);
    return 'data:image/png;base64,' + outBuf.toString('base64');
  } catch (e) {
    console.warn('[square-pad] skipped:', e.message);
    return dataUrl;
  }
}

module.exports = { padToSquare };
