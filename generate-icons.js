/**
 * Icon Generator for Live Call Firewall Extension
 * Creates shield icons at 16x16, 48x48, 128x128 as PNG files using canvas API
 * Run with: node generate-icons.js
 */
const fs = require('fs');
const path = require('path');

// Since we can't use external canvas in plain Node, we generate valid minimal PNGs
// These are real valid PNG files encoded as base64

// The icons directory
const iconsDir = path.join(__dirname, 'icons');
if (!fs.existsSync(iconsDir)) fs.mkdirSync(iconsDir);

function createMinimalPNG(size, svgContent) {
  // We'll write an SVG data URI wrapped in an HTML canvas approach
  // Since no canvas module, we create valid tiny PNGs using raw bytes

  // Generate a simple valid PNG programmatically
  const { createCanvas } = (() => {
    try { return require('canvas'); }
    catch(e) { return null; }
  })() || {};

  if (createCanvas) {
    const canvas = createCanvas(size, size);
    const ctx = canvas.getContext('2d');

    // Background
    ctx.fillStyle = '#0a0c19';
    ctx.fillRect(0, 0, size, size);

    // Shield shape
    const cx = size / 2;
    const cy = size / 2;
    const sw = size * 0.65;
    const sh = size * 0.75;

    ctx.fillStyle = '#6366f1';
    ctx.beginPath();
    ctx.moveTo(cx, cy - sh/2);
    ctx.lineTo(cx + sw/2, cy - sh/4);
    ctx.lineTo(cx + sw/2, cy + sh/8);
    ctx.quadraticCurveTo(cx + sw/2, cy + sh/2, cx, cy + sh/2);
    ctx.quadraticCurveTo(cx - sw/2, cy + sh/2, cx - sw/2, cy + sh/8);
    ctx.lineTo(cx - sw/2, cy - sh/4);
    ctx.closePath();
    ctx.fill();

    // Waveform inside shield
    if (size >= 32) {
      ctx.strokeStyle = '#06b6d4';
      ctx.lineWidth = Math.max(1, size * 0.04);
      ctx.lineCap = 'round';
      ctx.shadowColor = '#06b6d4';
      ctx.shadowBlur = size * 0.05;
      ctx.beginPath();
      const wavePoints = 8;
      const ww = sw * 0.6;
      const startX = cx - ww/2;
      for (let i = 0; i <= wavePoints; i++) {
        const x = startX + (ww * i / wavePoints);
        const amp = (i % 2 === 0) ? size * 0.05 : -size * 0.05;
        if (i === 0) ctx.moveTo(x, cy + amp);
        else ctx.lineTo(x, cy + amp);
      }
      ctx.stroke();
    }

    // Red dot (warning)
    if (size >= 16) {
      ctx.shadowBlur = 0;
      ctx.fillStyle = '#ef4444';
      const dotR = Math.max(2, size * 0.12);
      ctx.beginPath();
      ctx.arc(cx + sw/2 * 0.6, cy - sh/2 * 0.8, dotR, 0, Math.PI * 2);
      ctx.fill();
    }

    const buffer = canvas.toBuffer('image/png');
    fs.writeFileSync(path.join(iconsDir, `icon${size}.png`), buffer);
    console.log(`✅ Created icon${size}.png`);
  } else {
    // Fallback: Write a 1x1 valid PNG as placeholder
    // Real 1x1 transparent PNG in base64
    const PLACEHOLDER = Buffer.from(
      'iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAABmJLR0QA/wD/AP+gvaeTAAAADklEQVR42mNkYGBg+A8AAQQAAd4TAAAASUVORK5CYII=',
      'base64'
    );
    fs.writeFileSync(path.join(iconsDir, `icon${size}.png`), PLACEHOLDER);
    console.log(`⚠️  Created placeholder icon${size}.png (install 'canvas' package for real icons)`);
  }
}

[16, 48, 128].forEach(size => createMinimalPNG(size));
console.log('\n✅ Icon generation complete!');
console.log('   Icons saved to: icons/\n');
