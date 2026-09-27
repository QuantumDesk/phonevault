import qrcode from "qrcode-generator";

/**
 * A crisp QR code as an SVG string: one path, integer module grid, a 4-module quiet zone, and
 * `shape-rendering: crispEdges` so it scales without blur. Colors come from the caller so the
 * card around it controls contrast (dark modules on a light tile always, for scanners).
 */
export function qrSvg(text: string, opts: { dark?: string; light?: string; label?: string } = {}): string {
  const qr = qrcode(0, "M");
  qr.addData(text);
  qr.make();
  const n = qr.getModuleCount();
  const quiet = 4;
  const size = n + quiet * 2;
  let d = "";
  for (let r = 0; r < n; r++) {
    for (let c = 0; c < n; c++) {
      if (!qr.isDark(r, c)) continue;
      // merge horizontal runs into one rect-shaped subpath
      let run = 1;
      while (c + run < n && qr.isDark(r, c + run)) run++;
      d += `M${c + quiet} ${r + quiet}h${run}v1h-${run}z`;
      c += run - 1;
    }
  }
  const label = opts.label ? `<title>${opts.label.replace(/[<&>"]/g, "")}</title>` : "";
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" role="img" shape-rendering="crispEdges">${label}` +
    `<rect width="${size}" height="${size}" fill="${opts.light ?? "#fff"}"/><path d="${d}" fill="${opts.dark ?? "#000"}"/></svg>`;
}
