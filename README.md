# Nightshade Steg

<img src="steg.png">

A browser-first encrypted steganography application designed for static hosting (including Wasmer Edge). Files are processed locally in the browser; there is no application backend.

## Included

- AES-256-GCM authenticated encryption
- PBKDF2-SHA256 password-based key derivation
- 1-bit RGB LSB embedding for PNG/BMP carriers
- Binary-append mode for audio/video/other carriers
- Self-describing Nightshade payload format (magic + version + metadata + encrypted data)
- Original payload filename and MIME type recovery
- Drag-and-drop file selection
- Capacity feedback and progress stages
- Animated desktop/mobile UI with reduced-motion support
- Image and metadata previews
- Copy-details actions
- Smart decode auto-detection with image-LSB → binary-append fallback
- Local payload inspection plus multi-signal steganalysis for image carriers
- LSB entropy, chi-square even/odd analysis, neighboring-bit correlation, and RS-style regular/singular analysis
- Explainable metric panel with a bounded risk signal (not a calibrated probability)
- PWA/service-worker shell for repeat visits

## Important format notes

Image LSB mode always emits a fresh PNG. Binary-append mode keeps the carrier bytes first and adds the authenticated Nightshade package plus a footer. Decode mode auto-detection first attempts image LSB for image carriers and falls back to the binary-append footer.

The web UI intentionally does not upload files. Encryption and steganography happen in the browser.
The payload analyzer follows the same rule: it checks Nightshade markers locally. For PNG/BMP images it additionally performs multi-signal steganalysis using LSB entropy, chi-square even/odd balance, neighboring-bit correlation, and an RS-style regular/singular test. The displayed risk signal is a bounded heuristic for triage, not a calibrated probability and not proof of arbitrary steganography. Statistical tests can produce false positives on natural images and may miss JPEG-domain, transform-domain, palette, or otherwise non-LSB techniques.

## Build

```bash
npm install
npm run check
npm run build
```

The production site is emitted to `dist/`.

## Local preview

```bash
npm run preview
```

Then open `http://localhost:4173`.

