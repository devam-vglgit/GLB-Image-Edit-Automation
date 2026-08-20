// ─────────────────────────────────────────────────────────────
// Metal black-lift
// Targets the ONE persistent defect: near-black mirror reflections on the
// polished metal. It lifts only DARK, NEUTRAL (low-saturation) pixels up to a
// dark-grey floor, leaving mid-tones and highlights untouched (so the metal
// keeps its 3D gradient/form), and leaving GEMSTONES (coloured) and the WHITE
// background alone. This removes black patches WITHOUT the flattening a blanket
// brighten would cause.
// Tunable via env: METAL_FIX=off to disable; METAL_FLOOR (default 40),
// METAL_T (threshold below which pixels are lifted, default 60). Kept narrow
// and close together on purpose — this should only clean genuine near-black
// voids, not touch the broader mid-dark reflections that give metal its
// dimensional look. A wider range here flattens/washes out the metal.
// ─────────────────────────────────────────────────────────────
const Jimp = require('jimp');

async function liftMetalBlacks(dataUrl) {
  if (process.env.METAL_FIX === 'off') return dataUrl;
  try {
    const m = /^data:(.*?);base64,(.*)$/.exec(dataUrl || '');
    if (!m) return dataUrl;
    const img = await Jimp.read(Buffer.from(m[2], 'base64'));
    const data = img.bitmap.data, N = img.bitmap.width * img.bitmap.height;

    const FLOOR = Number(process.env.METAL_FLOOR) || 40;   // true-black voids lifted to this grey
    const T = Number(process.env.METAL_T) || 60;           // only lift pixels darker than this (narrow — near-black only)
    const SAT_MAX = 34;                                     // above this = coloured (gemstone) → skip
    const scale = (T - FLOOR) / T;

    for (let i = 0; i < N * 4; i += 4) {
      const r = data[i], g = data[i + 1], b = data[i + 2];
      const mx = Math.max(r, g, b), mn = Math.min(r, g, b), sat = mx - mn;
      if (mx >= 242 && sat <= 14) continue;   // white background → skip
      if (sat > SAT_MAX) continue;            // coloured (gemstone) → skip
      if (mx >= T) continue;                  // bright enough metal → leave (keeps form)
      // Dark neutral metal pixel → lift toward FLOOR..T (black point raised, no pure black)
      const nl = FLOOR + mx * scale;          // new brightness for this pixel
      const add = nl - mx;                    // equal shift keeps it neutral
      data[i] = Math.min(255, r + add);
      data[i + 1] = Math.min(255, g + add);
      data[i + 2] = Math.min(255, b + add);
    }

    const outBuf = await img.getBufferAsync(Jimp.MIME_PNG);
    return 'data:image/png;base64,' + outBuf.toString('base64');
  } catch (e) {
    console.warn('[metal-fix] skipped:', e.message);
    return dataUrl;
  }
}

module.exports = { liftMetalBlacks };
