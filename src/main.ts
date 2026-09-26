import './styles.css';
import { analyzeCarrier, decodeBinaryAppendCarrier, decodeImageCarrier, encodeBinaryAppendCarrier, encodeImageCarrier, getImageInfo } from './core/stego.js';
import { formatBytes, guessMode, hexDump, isImageCarrier, outputNameForBinary, outputNameForImage, previewText, setDownload } from './core/utils.js';
import { PBKDF2_ITERATIONS } from './core/crypto.js';

interface AppState {
  encPayload: File | null;
  encCarrier: File | null;
  encResult: { blob: Blob; name: string } | null;
  decCarrier: File | null;
  analysisCarrier: File | null;
  recovered: { data: Uint8Array; name: string; mime: string } | null;
  encPreviewUrl: string | null;
  recoveredPreviewUrl: string | null;
}

const state: AppState = {
  encPayload: null,
  encCarrier: null,
  encResult: null,
  decCarrier: null,
  analysisCarrier: null,
  recovered: null,
  encPreviewUrl: null,
  recoveredPreviewUrl: null,
};

const app = document.querySelector<HTMLDivElement>('#app')!;

app.innerHTML = `
  <div class="shell">
    <aside class="sidebar">
      <div>
        <div class="brand">
          <div class="brand-mark">NS</div>
          <div><div class="brand-name">NIGHTSHADE</div><div class="brand-sub">v1.0</div></div>
        </div>
        <div class="side-label">Operations</div>
        <div class="operation-switch" aria-label="Choose operation">
          <button class="nav-button active" data-view="encode" aria-pressed="true">Encode</button>
          <button class="nav-button" data-view="decode" aria-pressed="false">Decode</button>
          <button class="nav-button" data-view="analysis" aria-pressed="false">Analyze</button>
        </div>
      </div>
      <div class="security-card">
        <div class="security-top"><span class="pulse-dot"></span><span>LOCAL ONLY</span></div>
        <div class="security-copy">Files are processed in this browser.<br>Nothing is uploaded by Nightshade.</div>
        <div class="security-tags"><span>AES-256-GCM</span><span>PBKDF2-SHA256</span><span>1-BIT LSB</span></div>
      </div>
    </aside>

    <main class="main">
      <header class="header">
        <div>
          <div class="eyebrow">Encrypted steganography</div>
          <h1>Hide data inside ordinary files.</h1><div class="header-status"><span class="status-pip"></span><span id="headerStatus" aria-live="polite">READY · LOCAL PROCESSING</span></div>
        </div>
        <button class="ghost-button" id="resetBtn">Reset</button>
      </header>

      <section class="content">
        <div class="notice"><strong>Browser-native.</strong> Encryption, embedding, extraction, and decryption run locally. Your files do not need to leave this device.</div>

        <div id="encodeView" class="view active">
          <div class="section-heading"><h2>Encode and hide</h2></div>
          <div class="grid two">
            <div class="card">
              <div class="card-title">Payload</div>
              <label class="dropzone" id="payloadDropzone">
                <input type="file" id="payloadInput" hidden>
                <div class="drop-main" id="payloadName">Choose a file to hide</div>
                <div class="drop-sub" id="payloadMeta">Any file type. The original name and MIME type are preserved.</div>
              </label>
            </div>
            <div class="card">
              <div class="card-title">Carrier</div>
              <label class="dropzone" id="carrierDropzone">
                <input type="file" id="carrierInput" hidden>
                <div class="drop-main" id="carrierName">Choose a carrier</div>
                <div class="drop-sub" id="carrierMeta">PNG/BMP → LSB stego. Other files → binary append.</div>
              </label>
            </div>
          </div>

          <div class="card">
            <div class="card-title">Encryption + carrier mode</div>
            <div class="grid two">
              <div>
                <label class="field-label" for="encMode">Mode</label>
                <select class="input" id="encMode">
                  <option value="auto">Auto-detect</option>
                  <option value="image_lsb">Image LSB — PNG/BMP</option>
                  <option value="binary_append">Binary append — audio/video/other</option>
                </select>
              </div>
              <div>
                <label class="field-label" for="encPassword">Password</label>
                <div class="password-wrap"><input class="input" id="encPassword" type="password" placeholder="Strong password"><button class="mini-button" id="toggleEncPassword">Show</button></div>
              </div>
            </div>
            <div class="capacity" id="capacityBox">
              <div><span>Carrier capacity</span><strong id="capacityText">Select a carrier to calculate capacity.</strong></div>
              <div class="capacity-track"><div class="capacity-fill" id="capacityFill"></div></div>
            </div><center>
            <button class="primary-button" id="encodeBtn">Encrypt + hide</button>
            </center>
            <div class="progress" id="encodeProgress"><div class="progress-label"><span id="encodeStage">Idle</span><span id="encodePct">0%</span></div><div class="progress-track"><div id="encodeBar" class="progress-fill"></div></div></div>
            <div id="encodeMessage"></div>
          </div>

          <div class="grid two">
            <div class="card">
              <div class="card-title">Output</div>
              <div id="encodePreview" class="preview empty">Encrypt + hide a file to generate the output.</div>
              <div class="action-row"><button class="secondary-button" id="downloadEncode" disabled>Download output</button><button class="mini-button icon-button" id="copyEncodeInfo" disabled title="Copy output details">Copy details</button></div>
            </div>
            <div class="card">
              <div class="card-title">Activity monitor</div>
              <div class="log" id="encodeLog"></div>
            </div>
          </div>
        </div>

        <div id="decodeView" class="view">
          <div class="section-heading"><h2>Decode and recover</h2></div>
          <div class="card">
            <div class="card-title">Nightshade file</div>
            <label class="dropzone">
              <input type="file" id="decodeInput" hidden>
              <div class="drop-main" id="decodeName">Choose a stego file</div>
              <div class="drop-sub" id="decodeMeta">PNG/BMP LSB or Nightshade binary-append file.</div>
            </label>
            <div class="grid two compact-gap">
              <div>
                <label class="field-label" for="decMode">Decode mode</label>
                <select class="input" id="decMode">
                  <option value="auto">Auto-detect</option>
                  <option value="image_lsb">Image LSB</option>
                  <option value="binary_append">Binary append</option>
                </select>
              </div>
              <div>
                <label class="field-label" for="decPassword">Password</label>
                <div class="password-wrap"><input class="input" id="decPassword" type="password" placeholder="Password used for encoding"><button class="mini-button" id="toggleDecPassword">Show</button></div>
              </div>
            </div><center>
            <button class="primary-button" id="decodeBtn">Extract + decrypt</button>
            </center>
            <div class="progress"><div class="progress-label"><span id="decodeStage">Idle</span><span id="decodePct">0%</span></div><div class="progress-track"><div id="decodeBar" class="progress-fill"></div></div></div>
            <div id="decodeMessage"></div>
          </div>

          <div class="card analysis-card">
            <div class="analysis-heading"><div class="card-title">Steganalysis engine <span class="analysis-local">LOCAL</span></div><button class="mini-button" id="analyzeBtn" disabled>Analyze file</button></div>
            <div id="analysisResult" class="analysis-result empty">Choose a file to scan for a Nightshade payload or suspicious image LSB signals.</div>
            <div class="muted">Local steganalysis only. The risk signal combines several statistical tests; it is not a calibrated probability or proof of hidden data.</div>
          </div>

          <div class="grid two">
            <div class="card">
              <div class="card-title">Recovered payload</div>
              <div id="decodePreview" class="preview empty">Extract + decrypt a Nightshade file to preview the recovered payload.</div>
              <div class="action-row"><button class="secondary-button" id="saveRecovered" disabled>Save recovered file</button><button class="mini-button icon-button" id="copyRecoveredInfo" disabled title="Copy recovered details">Copy details</button></div>
            </div>
            <div class="card">
              <div class="card-title">Activity monitor</div>
              <div class="log" id="decodeLog"></div>
            </div>
          </div>
        </div>

        <div id="analysisView" class="view">
          <div class="section-heading"><h2>Analyze a file</h2></div>
          <div class="card">
            <div class="card-title">Steganalysis + payload inspection</div>
            <label class="dropzone" id="analysisDropzone">
              <input type="file" id="analysisInput" hidden>
              <div class="drop-main" id="analysisName">Choose a file to analyze</div>
              <div class="drop-sub" id="analysisMeta">Files stay in this browser. No password is required for the scan.</div>
            </label>
            <div class="grid two compact-gap">
              <div>
                <label class="field-label" for="analysisPassword">Password</label>
                <div class="password-wrap"><input class="input" id="analysisPassword" type="password" placeholder="Password used for encoding"><button class="mini-button" id="toggleAnalysisPassword">Show</button></div>
              </div>
              <div class="analysis-action-copy">The password is used locally only if a payload is detected.</div>
            </div>
            <center><button class="primary-button" id="standaloneAnalyzeBtn" disabled>Analyze file</button></center>
          </div>

          <div class="grid two">
            <div class="card">
              <div class="card-title">Analysis result</div>
              <div id="standaloneAnalysisResult" class="analysis-result empty">Choose a file to scan for a Nightshade payload or suspicious image LSB signals.</div>
              <div id="analysisRecovered" class="preview empty analysis-recovered">No decode attempt yet.</div>
              <div class="muted">Confirmed means a Nightshade marker was found. Possible means multiple statistical signals crossed heuristic thresholds; this is not proof of hidden content.</div>
            </div>
            <div class="card">
              <div class="card-title">Activity monitor</div>
              <div class="log" id="analysisLog"></div>
            </div>
          </div>
        </div>

        <footer class="footer">NIGHTSHADE STEG · Client-side processing · PBKDF2 ${PBKDF2_ITERATIONS.toLocaleString()} iterations · AES-256-GCM</footer>
      </section>
    </main>
  </div>
`;

const $ = <T extends Element>(selector: string) => document.querySelector<T>(selector)!;
const encodeView = $('#encodeView');
const decodeView = $('#decodeView');
const analysisView = $('#analysisView');

function escapeHtml(value: string): string {
  return value.replace(/[&<>\"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;', "'": '&#39;' }[char] as string));
}

function setBusy(target: 'encode' | 'decode', busy: boolean, idleText: string, busyText: string) {
  const button = $<HTMLButtonElement>(`#${target}Btn`);
  button.classList.toggle('is-busy', busy);
  button.textContent = busy ? busyText : idleText;
  $(`#headerStatus`).textContent = busy ? `${target.toUpperCase()} · PROCESSING LOCALLY` : 'READY · LOCAL PROCESSING';
}

function revokePreviewUrls() {
  if (state.encPreviewUrl) URL.revokeObjectURL(state.encPreviewUrl);
  if (state.recoveredPreviewUrl) URL.revokeObjectURL(state.recoveredPreviewUrl);
  state.encPreviewUrl = null;
  state.recoveredPreviewUrl = null;
}

function renderFilePreview(containerId: string, data: Uint8Array, name: string, mime: string) {
  if (containerId === '#encodePreview' && state.encPreviewUrl) URL.revokeObjectURL(state.encPreviewUrl);
  if (containerId === '#decodePreview' && state.recoveredPreviewUrl) URL.revokeObjectURL(state.recoveredPreviewUrl);
  const container = $<HTMLDivElement>(containerId);
  const safeName = escapeHtml(name);
  const safeMime = escapeHtml(mime || 'application/octet-stream');
  const blob = new Blob([new Uint8Array(data)], { type: mime || 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  if (containerId === '#encodePreview') state.encPreviewUrl = url;
  if (containerId === '#decodePreview') state.recoveredPreviewUrl = url;

  const isVisual = mime.startsWith('image/');
  container.className = 'preview';
  container.innerHTML = `
    <div class="stat-list">
      <div><span>File</span><strong>${safeName}</strong></div>
      <div><span>Size</span><strong>${formatBytes(data.byteLength)}</strong></div>
      <div><span>Type</span><strong>${safeMime}</strong></div>
    </div>
    ${isVisual ? `<img class="preview-media" src="${url}" alt="${safeName}" />` : `<div class="preview-binary"><span class="preview-binary-icon">BIN</span><div><strong>Binary payload</strong><div class="muted">Preview is intentionally limited to metadata and a safe byte sample.</div></div></div>`}`;
}

function setProgressStage(target: 'encode' | 'decode', fraction: number, stage: string) {
  setProgress(target, fraction, stage);
  requestAnimationFrame(() => {
    const fill = $<HTMLDivElement>(`#${target}Bar`);
    fill.style.width = `${Math.round(fraction * 100)}%`;
  });
}

function log(target: 'encode' | 'decode' | 'analysis', message: string, error = false) {
  const box = $<HTMLDivElement>(`#${target}Log`);
  const row = document.createElement('div');
  row.className = `log-line${error ? ' error' : ''}`;
  row.textContent = `>> ${message}`;
  box.appendChild(row);
  box.scrollTop = box.scrollHeight;
}

function setProgress(target: 'encode' | 'decode', fraction: number, stage: string) {
  $<HTMLDivElement>(`#${target}Bar`).style.width = `${Math.round(fraction * 100)}%`;
  $(`#${target}Pct`).textContent = `${Math.round(fraction * 100)}%`;
  $(`#${target}Stage`).textContent = stage;
}

function showMessage(target: 'encode' | 'decode', message: string, type: 'success' | 'error') {
  $(`#${target}Message`).innerHTML = `<div class="message ${type}">${message}</div>`;
}

function clearMessage(target: 'encode' | 'decode') {
  $(`#${target}Message`).innerHTML = '';
}

function selectedEncodeMode(): 'image_lsb' | 'binary_append' {
  const selected = $<HTMLSelectElement>('#encMode').value;
  return selected === 'auto' ? guessMode(state.encCarrier) : selected as 'image_lsb' | 'binary_append';
}

function selectedDecodeMode(): 'auto' | 'image_lsb' | 'binary_append' {
  const selected = $<HTMLSelectElement>('#decMode').value;
  return selected as 'auto' | 'image_lsb' | 'binary_append';
}

async function updateCapacity() {
  if (!state.encCarrier) {
    $('#capacityText').textContent = 'Select a carrier to calculate capacity.';
    $<HTMLDivElement>('#capacityFill').style.width = '0%';
    return;
  }
  const mode = selectedEncodeMode();
  if (mode === 'binary_append') {
    $('#capacityText').textContent = 'No carrier capacity limit; the encrypted package is appended to the carrier.';
    $<HTMLDivElement>('#capacityFill').style.width = '0%';
    return;
  }
  try {
    const info = await getImageInfo(state.encCarrier);
    const hint = state.encPayload ? ` · payload ${formatBytes(state.encPayload.size)}` : '';
    $('#capacityText').textContent = `${formatBytes(info.capacityBytes)} raw LSB capacity · ${info.width}×${info.height}${hint}`;
    const estimated = state.encPayload ? Math.min(100, ((state.encPayload.size + 45 + 28) / info.capacityBytes) * 100) : 0;
    $<HTMLDivElement>('#capacityFill').style.width = `${Math.max(estimated, 3)}%`;
    $('#capacityBox').classList.toggle('capacity-warning', Boolean(state.encPayload && estimated > 80));
  } catch (error) {
    $('#capacityText').textContent = error instanceof Error ? error.message : 'Unable to inspect the carrier.';
    $<HTMLDivElement>('#capacityFill').style.width = '0%';
  }
}

function wireDropzone(zoneId: string, inputId: string, handler: (file: File) => void) {
  const zone = $<HTMLLabelElement>(zoneId);
  const input = $<HTMLInputElement>(inputId);
  input.addEventListener('change', () => { const file = input.files?.[0]; if (file) handler(file); });
  ['dragenter', 'dragover'].forEach((eventName) => zone.addEventListener(eventName, (event) => { event.preventDefault(); zone.classList.add('dragging'); }));
  ['dragleave', 'drop'].forEach((eventName) => zone.addEventListener(eventName, (event) => { event.preventDefault(); zone.classList.remove('dragging'); }));
  zone.addEventListener('drop', (event) => { const file = event.dataTransfer?.files?.[0]; if (file) handler(file); });
}

wireDropzone('#payloadDropzone', '#payloadInput', (file) => {
  state.encPayload = file;
  $('#payloadName').textContent = file.name;
  $('#payloadMeta').textContent = `${formatBytes(file.size)} · ${file.type || 'application/octet-stream'}`;
  clearMessage('encode');
  log('encode', `PAYLOAD READY → ${file.name}`);
  updateCapacity();
});

wireDropzone('#carrierDropzone', '#carrierInput', (file) => {
  state.encCarrier = file;
  const mode = guessMode(file);
  $('#carrierName').textContent = file.name;
  $('#carrierMeta').textContent = `${formatBytes(file.size)} · ${mode === 'image_lsb' ? 'PNG/BMP image carrier' : 'binary append carrier'}`;
  if ($<HTMLSelectElement>('#encMode').value === 'auto') log('encode', `AUTO MODE → ${mode}`);
  clearMessage('encode');
  updateCapacity();
});

const decodeLabel = $('#decodeInput').parentElement as HTMLLabelElement;
['dragenter', 'dragover'].forEach((eventName) => decodeLabel.addEventListener(eventName, (event) => { event.preventDefault(); decodeLabel.classList.add('dragging'); }));
['dragleave', 'drop'].forEach((eventName) => decodeLabel.addEventListener(eventName, (event) => { event.preventDefault(); decodeLabel.classList.remove('dragging'); }));
decodeLabel.addEventListener('drop', (event) => { const file = event.dataTransfer?.files?.[0]; if (file) setDecodeCarrier(file); });
$('#decodeInput').addEventListener('change', () => { const file = $<HTMLInputElement>('#decodeInput').files?.[0]; if (file) setDecodeCarrier(file); });

function setDecodeCarrier(file: File) {
  state.decCarrier = file;
  $('#decodeName').textContent = file.name;
  $('#decodeMeta').textContent = `${formatBytes(file.size)} · ${isImageCarrier(file) ? 'image carrier' : 'binary carrier'}`;
  clearMessage('decode');
  $<HTMLButtonElement>('#analyzeBtn').disabled = false;
  runCarrierAnalysis(file);
  if ($<HTMLSelectElement>('#decMode').value === 'auto') log('decode', `AUTO MODE → ${isImageCarrier(file) ? 'image_lsb' : 'binary_append'}`);
}

let analysisRequest = 0;
async function runCarrierAnalysis(file: File, resultSelector = '#analysisResult', logTarget: 'decode' | 'analysis' = 'decode') {
  const request = ++analysisRequest;
  const result = $<HTMLDivElement>(resultSelector);
  result.className = 'analysis-result scanning';
  result.textContent = 'Scanning local file structure and signal patterns…';
  try {
    const analysis = await analyzeCarrier(file);
    if (request !== analysisRequest) return;
    result.className = `analysis-result ${analysis.verdict}`;
    const metadata = analysis.metadata ? `<div class="analysis-metadata"><div><span>Original file</span><strong>${escapeHtml(analysis.metadata.name)}</strong></div><div><span>Format</span><strong>${escapeHtml(analysis.metadata.mime)}</strong></div><div><span>Estimated data</span><strong>${formatBytes(analysis.metadata.estimatedDataBytes)}</strong></div><div><span>Encrypted package</span><strong>${formatBytes(analysis.metadata.packageBytes)}</strong></div></div>` : '';
    const metrics = analysis.metrics ? `<div class="steg-metrics">
      <div><span>LSB entropy</span><strong>${analysis.metrics.lsbEntropy.toFixed(3)}</strong></div>
      <div><span>Chi-square p</span><strong>${analysis.metrics.chiSquareP.toFixed(3)}</strong></div>
      <div><span>Neighbor correlation</span><strong>${analysis.metrics.neighborCorrelation.toFixed(3)}</strong></div>
      <div><span>Bit transition rate</span><strong>${(analysis.metrics.transitionRate * 100).toFixed(1)}%</strong></div>
      <div><span>RS regular</span><strong>${(analysis.metrics.rsRegular * 100).toFixed(1)}%</strong></div>
      <div><span>RS singular</span><strong>${(analysis.metrics.rsSingular * 100).toFixed(1)}%</strong></div>
    </div>` : '';
    result.innerHTML = `<div class="analysis-status"><strong>${escapeHtml(analysis.title)}</strong><span>${analysis.score}% risk signal</span></div><div>${escapeHtml(analysis.detail)}</div>${metrics}${metadata}<div class="analysis-method">METHOD · ${escapeHtml(analysis.method)}</div>`;
    log(logTarget, `ANALYSIS → ${analysis.title.toUpperCase()}`);
    return analysis;
  } catch (error) {
    if (request !== analysisRequest) return;
    result.className = 'analysis-result error';
    result.textContent = error instanceof Error ? error.message : 'Unable to analyze this file.';
    return null;
  }
}

$('#analyzeBtn').addEventListener('click', () => {
  if (state.decCarrier) runCarrierAnalysis(state.decCarrier);
});

wireDropzone('#analysisDropzone', '#analysisInput', (file) => {
  state.analysisCarrier = file;
  $('#analysisName').textContent = file.name;
  $('#analysisMeta').textContent = `${formatBytes(file.size)} · ${file.type || 'application/octet-stream'}`;
  $<HTMLButtonElement>('#standaloneAnalyzeBtn').disabled = false;
  log('analysis', `FILE READY → ${file.name}`);
  runCarrierAnalysis(file, '#standaloneAnalysisResult', 'analysis');
});

async function tryDecodeAnalyzedFile(file: File, password: string) {
  try {
    let result: { data: Uint8Array; name: string; mime: string };
    if (isImageCarrier(file)) {
      try { result = await decodeImageCarrier(file, password); }
      catch { result = await decodeBinaryAppendCarrier(file, password); }
    } else {
      result = await decodeBinaryAppendCarrier(file, password);
    }
    renderFilePreview('#analysisRecovered', result.data, result.name, result.mime);
    $('#analysisRecovered').insertAdjacentHTML('beforeend', `<div class="preview-text"><div class="preview-kicker">Text sample</div><div>${escapeHtml(previewText(result.data))}</div><div class="preview-kicker">Hex sample</div><div>${hexDump(result.data)}</div></div>`);
    log('analysis', `DECODE VERIFIED → ${result.name}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Decode failed.';
    const result = $<HTMLDivElement>('#analysisRecovered');
    result.className = 'analysis-result error';
    result.textContent = `Decode attempt failed: ${message}`;
    log('analysis', `DECODE FAILED → ${message}`, true);
  }
}

$('#standaloneAnalyzeBtn').addEventListener('click', async () => {
  if (!state.analysisCarrier) return;
  const button = $<HTMLButtonElement>('#standaloneAnalyzeBtn');
  const password = $<HTMLInputElement>('#analysisPassword').value;
  button.disabled = true;
  button.textContent = 'Scanning…';
  const analysis = await runCarrierAnalysis(state.analysisCarrier, '#standaloneAnalysisResult', 'analysis');
  if (analysis?.verdict === 'confirmed' || analysis?.verdict === 'possible') {
    if (!password) {
      $('#standaloneAnalysisResult').insertAdjacentHTML('beforeend', '<div class="analysis-next">Enter the password above, then analyze again to try decoding.</div>');
    } else {
      button.textContent = 'Decoding…';
      await tryDecodeAnalyzedFile(state.analysisCarrier, password);
    }
  }
  button.disabled = false;
  button.textContent = 'Analyze + try decode';
});

$('#encMode').addEventListener('change', updateCapacity);
$('#toggleEncPassword').addEventListener('click', () => { const input = $<HTMLInputElement>('#encPassword'); input.type = input.type === 'password' ? 'text' : 'password'; $('#toggleEncPassword').textContent = input.type === 'password' ? 'Show' : 'Hide'; });
$('#toggleDecPassword').addEventListener('click', () => { const input = $<HTMLInputElement>('#decPassword'); input.type = input.type === 'password' ? 'text' : 'password'; $('#toggleDecPassword').textContent = input.type === 'password' ? 'Show' : 'Hide'; });
$('#toggleAnalysisPassword').addEventListener('click', () => { const input = $<HTMLInputElement>('#analysisPassword'); input.type = input.type === 'password' ? 'text' : 'password'; $('#toggleAnalysisPassword').textContent = input.type === 'password' ? 'Show' : 'Hide'; });

function activateView(view: 'encode' | 'decode' | 'analysis') {
  document.querySelectorAll<HTMLButtonElement>('.nav-button').forEach((element) => {
    const active = element.dataset.view === view;
    element.classList.toggle('active', active);
    element.setAttribute('aria-pressed', String(active));
  });
  document.body.classList.add('view-switching');
  encodeView.classList.toggle('active', view === 'encode');
  decodeView.classList.toggle('active', view === 'decode');
  analysisView.classList.toggle('active', view === 'analysis');
  log(view, 'VIEW OPENED');
  window.setTimeout(() => document.body.classList.remove('view-switching'), 420);
}

for (const button of document.querySelectorAll<HTMLButtonElement>('.nav-button')) {
  button.addEventListener('click', () => activateView(button.dataset.view as 'encode' | 'decode' | 'analysis'));
}

let switchTouchStart = 0;
const operationSwitch = document.querySelector<HTMLElement>('.operation-switch')!;
operationSwitch.addEventListener('touchstart', (event) => { switchTouchStart = event.changedTouches[0].clientX; }, { passive: true });
operationSwitch.addEventListener('touchend', (event) => {
  const distance = event.changedTouches[0].clientX - switchTouchStart;
  if (Math.abs(distance) < 35) return;
  activateView(distance < 0 ? 'decode' : 'encode');
}, { passive: true });

$('#encodeBtn').addEventListener('click', async () => {
  clearMessage('encode');
  if (!state.encPayload || !state.encCarrier) return showMessage('encode', 'Choose both a payload and a carrier.', 'error');
  const password = $<HTMLInputElement>('#encPassword').value;
  if (!password) return showMessage('encode', 'Enter an encryption password.', 'error');

  const btn = $<HTMLButtonElement>('#encodeBtn');
  btn.disabled = true;
  setBusy('encode', true, 'Encrypt + hide', 'Processing…');
  clearMessage('encode');
  setProgress('encode', 0.05, 'Reading payload…');
  log('encode', `PAYLOAD → ${state.encPayload.name} (${formatBytes(state.encPayload.size)})`);
  try {
    const payload = new Uint8Array(await state.encPayload.arrayBuffer());
    setProgress('encode', 0.22, 'Encrypting with AES-256-GCM…');
    log('encode', `PBKDF2-SHA256 → ${PBKDF2_ITERATIONS.toLocaleString()} iterations`);
    const mode = selectedEncodeMode();
    setProgress('encode', 0.45, mode === 'image_lsb' ? 'Embedding encrypted bytes into LSBs…' : 'Appending encrypted package…');

    if (mode === 'image_lsb') {
      const result = await encodeImageCarrier(state.encCarrier, payload, password, state.encPayload.name, state.encPayload.type);
      const name = outputNameForImage(state.encCarrier.name);
      state.encResult = { blob: result.blob, name };
      renderFilePreview('#encodePreview', new Uint8Array(await result.blob.arrayBuffer()), name, 'image/png');
      $('#encodePreview').insertAdjacentHTML('afterbegin', `<div class="mode-chip">IMAGE LSB · ${result.info.width}×${result.info.height} · PACKAGE ${formatBytes(result.packageBytes)}</div>`);
    } else {
      const result = await encodeBinaryAppendCarrier(state.encCarrier, payload, password, state.encPayload.name, state.encPayload.type);
      const name = outputNameForBinary(state.encCarrier.name);
      state.encResult = { blob: result.blob, name };
      const outputBytes = new Uint8Array(await result.blob.arrayBuffer());
      renderFilePreview('#encodePreview', outputBytes.slice(0, Math.min(outputBytes.length, 64 * 1024)), name, state.encCarrier.type || 'application/octet-stream');
      $('#encodePreview').insertAdjacentHTML('afterbegin', `<div class="mode-chip">BINARY APPEND · CARRIER ${formatBytes(state.encCarrier.size)} · PACKAGE ${formatBytes(result.packageBytes)}</div><p class="muted">Original carrier bytes remain intact at the beginning; the authenticated package is appended at EOF.</p>`);
    }

    setProgress('encode', 1, 'Done');
    log('encode', 'ENCRYPTION VERIFIED // OUTPUT READY');
    showMessage('encode', `Output ready: <strong>${escapeHtml(state.encResult.name)}</strong>`, 'success');
    $<HTMLButtonElement>('#copyEncodeInfo').disabled = false;
    $<HTMLButtonElement>('#downloadEncode').disabled = false;
  } catch (error) {
    setProgress('encode', 0, 'Failed');
    log('encode', error instanceof Error ? error.message : 'Unknown error', true);
    showMessage('encode', escapeHtml(error instanceof Error ? error.message : 'Encoding failed.'), 'error');
  } finally {
    btn.disabled = false;
    setBusy('encode', false, 'Encrypt + hide', 'Processing…');
  }
});

$('#downloadEncode').addEventListener('click', () => { if (state.encResult) setDownload(state.encResult.blob, state.encResult.name); });

$('#decodeBtn').addEventListener('click', async () => {
  clearMessage('decode');
  if (!state.decCarrier) return showMessage('decode', 'Choose a stego file.', 'error');
  const password = $<HTMLInputElement>('#decPassword').value;
  if (!password) return showMessage('decode', 'Enter the decryption password.', 'error');

  const btn = $<HTMLButtonElement>('#decodeBtn');
  btn.disabled = true;
  setBusy('decode', true, 'Extract + decrypt', 'Processing…');
  setProgress('decode', 0.08, 'Reading carrier…');
  log('decode', `CARRIER → ${state.decCarrier.name}`);
  try {
    const selectedMode = selectedDecodeMode();
    let mode: 'image_lsb' | 'binary_append';
    let result;
    if (selectedMode === 'auto') {
      if (isImageCarrier(state.decCarrier)) {
        try {
          mode = 'image_lsb';
          log('decode', 'AUTO → trying image LSB');
          setProgress('decode', 0.35, 'Extracting LSB package…');
          result = await decodeImageCarrier(state.decCarrier, password);
        } catch {
          mode = 'binary_append';
          log('decode', 'LSB payload not found → trying binary append');
          setProgress('decode', 0.48, 'Checking Nightshade footer…');
          result = await decodeBinaryAppendCarrier(state.decCarrier, password);
        }
      } else {
        mode = 'binary_append';
        log('decode', 'AUTO → binary append');
        setProgress('decode', 0.35, 'Reading Nightshade footer…');
        result = await decodeBinaryAppendCarrier(state.decCarrier, password);
      }
    } else {
      mode = selectedMode;
      log('decode', `MODE → ${mode}`);
      setProgress('decode', 0.35, mode === 'image_lsb' ? 'Extracting LSB package…' : 'Reading Nightshade footer…');
      result = mode === 'image_lsb'
        ? await decodeImageCarrier(state.decCarrier, password)
        : await decodeBinaryAppendCarrier(state.decCarrier, password);
    }

    setProgress('decode', 0.82, 'Authenticating and decrypting…');
    state.recovered = { data: result.data, name: result.name, mime: result.mime };
    renderFilePreview('#decodePreview', result.data, result.name, result.mime);
    $('#decodePreview').insertAdjacentHTML('beforeend', `<div class="preview-text"><div class="preview-kicker">Text sample</div><div>${escapeHtml(previewText(result.data))}</div><div class="preview-kicker">Hex sample</div><div>${hexDump(result.data)}</div></div>`);
    setProgress('decode', 1, 'Done');
    log('decode', 'DECRYPTION VERIFIED // PAYLOAD RECOVERED');
    showMessage('decode', `Recovered <strong>${escapeHtml(result.name)}</strong> successfully.`, 'success');
    $<HTMLButtonElement>('#saveRecovered').disabled = false;
    $<HTMLButtonElement>('#copyRecoveredInfo').disabled = false;
  } catch (error) {
    setProgress('decode', 0, 'Failed');
    log('decode', error instanceof Error ? error.message : 'Unknown error', true);
    showMessage('decode', escapeHtml(error instanceof Error ? error.message : 'Decoding failed.'), 'error');
  } finally {
    btn.disabled = false;
    setBusy('decode', false, 'Extract + decrypt', 'Processing…');
  }
});

async function copyText(value: string, target: 'encode' | 'decode') {
  try {
    await navigator.clipboard.writeText(value);
    showMessage(target, 'Details copied to the clipboard.', 'success');
  } catch {
    showMessage(target, 'Clipboard access is unavailable in this browser context.', 'error');
  }
}

$('#copyEncodeInfo').addEventListener('click', () => {
  if (!state.encResult) return;
  copyText(`Nightshade output: ${state.encResult.name}\nSize: ${formatBytes(state.encResult.blob.size)}`, 'encode');
});
$('#copyRecoveredInfo').addEventListener('click', () => {
  if (!state.recovered) return;
  copyText(`Recovered file: ${state.recovered.name}\nSize: ${formatBytes(state.recovered.data.byteLength)}\nMIME: ${state.recovered.mime || 'application/octet-stream'}`, 'decode');
});

$('#saveRecovered').addEventListener('click', () => {
  if (!state.recovered) return;
  const blob = new Blob([new Uint8Array(state.recovered.data)], { type: state.recovered.mime || 'application/octet-stream' });
  setDownload(blob, state.recovered.name || 'recovered-file.bin');
});

$('#resetBtn').addEventListener('click', () => {
  state.encPayload = null;
  state.encCarrier = null;
  state.encResult = null;
  state.decCarrier = null;
  state.analysisCarrier = null;
  state.recovered = null;
  analysisRequest += 1;
  revokePreviewUrls();
  setBusy('encode', false, 'Encrypt + hide', 'Processing…');
  setBusy('decode', false, 'Extract + decrypt', 'Processing…');
  document.querySelectorAll<HTMLInputElement>('input[type=file]').forEach((input) => input.value = '');
  $<HTMLInputElement>('#encPassword').value = '';
  $<HTMLInputElement>('#decPassword').value = '';
  $<HTMLInputElement>('#analysisPassword').value = '';
  $<HTMLSelectElement>('#encMode').value = 'auto';
  $<HTMLSelectElement>('#decMode').value = 'auto';
  $('#payloadName').textContent = 'Choose a file to hide';
  $('#payloadMeta').textContent = 'Any file type. The original name and MIME type are preserved.';
  $('#carrierName').textContent = 'Choose a carrier';
  $('#carrierMeta').textContent = 'PNG/BMP → LSB stego. Other files → binary append.';
  $('#decodeName').textContent = 'Choose a stego file';
  $('#decodeMeta').textContent = 'PNG/BMP LSB or Nightshade binary-append file.';
  $('#analysisName').textContent = 'Choose a file to analyze';
  $('#analysisMeta').textContent = 'Files stay in this browser. No password is required for the scan.';
  $<HTMLButtonElement>('#standaloneAnalyzeBtn').disabled = true;
  const standaloneAnalysisResult = $<HTMLDivElement>('#standaloneAnalysisResult');
  standaloneAnalysisResult.className = 'analysis-result empty';
  standaloneAnalysisResult.textContent = 'Choose a file to scan for a Nightshade payload or suspicious image LSB signals.';
  $('#analysisRecovered').className = 'preview empty analysis-recovered';
  $('#analysisRecovered').textContent = 'No decode attempt yet.';
  $<HTMLButtonElement>('#analyzeBtn').disabled = true;
  const analysisResult = $<HTMLDivElement>('#analysisResult');
  analysisResult.className = 'analysis-result empty';
  analysisResult.textContent = 'Choose a file to scan for a Nightshade payload or suspicious image LSB signals.';
  $('#encodePreview').className = 'preview empty';
  $('#encodePreview').textContent = 'Encrypt + hide a file to generate the output.';
  $('#decodePreview').className = 'preview empty';
  $('#decodePreview').textContent = 'Extract + decrypt a Nightshade file to preview the recovered payload.';
  $<HTMLButtonElement>('#downloadEncode').disabled = true;
  $<HTMLButtonElement>('#saveRecovered').disabled = true;
  $<HTMLButtonElement>('#copyEncodeInfo').disabled = true;
  $<HTMLButtonElement>('#copyRecoveredInfo').disabled = true;
  clearMessage('encode'); clearMessage('decode');
  setProgress('encode', 0, 'Idle'); setProgress('decode', 0, 'Idle');
  $('#encodeLog').innerHTML = ''; $('#decodeLog').innerHTML = '';
  $('#analysisLog').innerHTML = '';
  log('encode', 'NIGHTSHADE READY'); log('decode', 'NIGHTSHADE READY');
  log('analysis', 'NIGHTSHADE READY');
  updateCapacity();
});

log('encode', 'NIGHTSHADE ONLINE');
log('encode', 'AES-256-GCM / PBKDF2-SHA256');
log('encode', 'IMAGE: 1-BIT RGB LSB | OTHER: BINARY APPEND');
log('decode', 'NIGHTSHADE ONLINE');
log('decode', 'WAITING FOR LOCAL FILE');

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js').catch(() => undefined);
}
