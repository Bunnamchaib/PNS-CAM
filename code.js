/* Secure Vault - client logic.
 * Credentials, photos and decrypted images exist only in RAM.
 * Nothing is written to localStorage / IndexedDB / Photos library. */
'use strict';

(() => {
  // ------------------------------------------------------------------ config
  const BACKEND_URL = 'https://script.google.com/macros/s/AKfycbxwz84Oje3AxITzivyD9Q6Co9V8pa4H1rMj_-u2CFVSkrvnwHImFpwnHezmj6DNTcAZ/exec';
  const MAX_EDGE = 1600;            // longest edge of uploaded photo (px)
  const JPEG_QUALITY = 0.85;
  const PBKDF2_ITER = 250000;
  const IDLE_LOCK_MS = 120000;      // lock after 2 min without interaction
  const HIDDEN_LOCK_MS = 60000;     // lock after 60 s in background
  const REQUEST_TIMEOUT_MS = 90000;

  const enc = new TextEncoder();
  const dec = new TextDecoder();

  // ------------------------------------------------------------------- state
  const state = {
    url: null,
    pass: null,
    stream: null,
    raf: 0,
    facing: 'environment',
    captured: null,      // JPEG data URL (RAM only)
    items: [],
    tab: 'capture',
    busy: false
  };
  let idleTimer = 0;
  let hiddenTimer = 0;
  let toastTimer = 0;
  let sessionEpoch = 0;
  const calculator = new Calculator();

  // ---------------------------------------------------------------- elements
  const el = {};
  [
    'calculator', 'calcDisplay', 'calcExpression', 'calcClear', 'gate', 'gateCancel', 'gatePass', 'gateBtn', 'gateMsg', 'app', 'headerTitle', 'lockBtn',
    'tabCapture', 'tabVault', 'navCapture', 'navVault', 'preview', 'video', 'camMsg',
    'camMsgText', 'camStart', 'flipBtn', 'shutterBtn', 'retakeBtn', 'uploadBtn',
    'ctrlLive', 'ctrlReview', 'refreshBtn', 'list', 'listEmpty', 'viewer', 'viewerCanvas',
    'viewerClose', 'viewerMsg', 'viewerTitle', 'toast'
  ].forEach((id) => { el[id] = document.getElementById(id); });
  const pctx = el.preview.getContext('2d');

  // ----------------------------------------------------------------- helpers
  function toast(msg, kind) {
    el.toast.textContent = msg;
    el.toast.className = 'toast show ' + (kind || '');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.toast.className = 'toast'; }, 3400);
  }

  function friendly(e) {
    if (e instanceof TypeError) {
      return 'Network error. Check the URL, your connection, and that the deployment allows access for "Anyone".';
    }
    return e && e.message ? e.message : 'Something went wrong';
  }

  function bytesToB64(bytes) {
    let s = '';
    const CH = 0x8000;
    for (let i = 0; i < bytes.length; i += CH) {
      s += String.fromCharCode.apply(null, bytes.subarray(i, i + CH));
    }
    return btoa(s);
  }

  function b64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function fmtDate(ts) {
    try {
      return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' }).format(new Date(ts));
    } catch (_) {
      return new Date(ts).toLocaleString();
    }
  }

  // ------------------------------------------------------------------ crypto
  async function deriveKey(pass, salt, usage) {
    const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' },
      base,
      { name: 'AES-GCM', length: 256 },
      false,
      [usage]
    );
  }

  // Output: "v1.<salt>.<iv>.<ciphertext>"  (all Base64)
  async function encryptText(plain) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(state.pass, salt, 'encrypt');
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plain)));
    return 'v1.' + bytesToB64(salt) + '.' + bytesToB64(iv) + '.' + bytesToB64(ct);
  }

  async function decryptText(packed) {
    const parts = String(packed).trim().split('.');
    if (parts.length !== 4 || parts[0] !== 'v1') throw new Error('Unsupported file format');
    try {
      const salt = b64ToBytes(parts[1]);
      const iv = b64ToBytes(parts[2]);
      const ct = b64ToBytes(parts[3]);
      const key = await deriveKey(state.pass, salt, 'decrypt');
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
      return dec.decode(pt);
    } catch (_) {
      throw new Error('Decryption failed. The file was encrypted with a different password, or it is corrupted.');
    }
  }

  // --------------------------------------------------------------------- API
  async function api(action, payload) {
    if (!state.url || state.pass === null) throw new Error('Locked');
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), REQUEST_TIMEOUT_MS);
    try {
      const res = await fetch(state.url, {
        method: 'POST',
        // text/plain avoids a CORS preflight, which Apps Script cannot answer
        headers: { 'Content-Type': 'text/plain;charset=utf-8' },
        body: JSON.stringify(Object.assign({}, payload || {}, { action: action, password: state.pass })),
        redirect: 'follow',
        credentials: 'omit',
        cache: 'no-store',
        referrerPolicy: 'no-referrer',
        signal: ctrl.signal
      });
      if (!res.ok) throw new Error('Server responded with ' + res.status);
      let json;
      try { json = await res.json(); } catch (_) {
        throw new Error('Unexpected server response. Redeploy the script with access set to "Anyone".');
      }
      if (!json || json.ok !== true) throw new Error((json && json.error) || 'Request failed');
      return json;
    } catch (e) {
      if (e && e.name === 'AbortError') throw new Error('Request timed out');
      throw e;
    } finally {
      clearTimeout(timer);
    }
  }

  // -------------------------------------------------------------- login gate
  function gateMessage(text, info) {
    el.gateMsg.textContent = text || '';
    el.gateMsg.className = info ? 'info' : '';
  }

  async function login() {
    if (state.busy) return;
    const pass = el.gatePass.value;
    if (!pass) return gateMessage('Enter your password.');

    const attempt = ++sessionEpoch;
    state.busy = true;
    el.gateBtn.disabled = true;
    el.gateBtn.textContent = 'Verifying…';
    gateMessage('');
    state.url = BACKEND_URL;
    state.pass = pass;
    try {
      const r = await api('fetch_list');
      if (attempt !== sessionEpoch) return;
      state.items = r.files || [];
      el.gatePass.value = '';
      showApp();
      renderList();
    } catch (e) {
      if (attempt !== sessionEpoch) return;
      state.url = null;
      state.pass = null;
      gateMessage(friendly(e));
    } finally {
      if (attempt === sessionEpoch) {
        state.busy = false;
        el.gateBtn.disabled = false;
        el.gateBtn.textContent = 'Unlock';
      }
    }
  }

  function showApp() {
    el.gate.close();
    el.gate.hidden = true;
    el.calculator.hidden = true;
    el.app.hidden = false;
    armIdleTimer();
    setTab('capture');
  }

  function lock(reason) {
    sessionEpoch++;
    stopCamera(false);
    closeViewer();
    wipeCapture();
    state.url = null;
    state.pass = null;
    state.items = [];
    state.busy = false;
    el.list.textContent = '';
    el.app.hidden = true;
    el.gate.close();
    el.gate.hidden = true;
    el.calculator.hidden = false;
    el.gatePass.value = '';
    el.gateBtn.disabled = false;
    el.gateBtn.textContent = 'Unlock';
    el.toast.className = 'toast';
    clearTimeout(toastTimer);
    calculator.reset();
    el.calcDisplay.textContent = '0';
    el.calcExpression.textContent = '';
    clearTimeout(idleTimer);
    clearTimeout(hiddenTimer);
    gateMessage('');
    el.calcClear.focus();
  }

  function pressCalculator(key) {
    const result = calculator.press(key);
    el.calcDisplay.textContent = result.display;
    el.calcExpression.textContent = result.expression.replace(/\*/g, '×').replace(/\//g, '÷');
    if (result.unlock) {
      gateMessage('');
      el.gatePass.value = '';
      el.gate.hidden = false;
      el.gate.showModal();
      el.gatePass.focus();
    }
  }

  function armIdleTimer() {
    clearTimeout(idleTimer);
    if (!state.pass) return;
    idleTimer = setTimeout(() => lock('Locked after inactivity.'), IDLE_LOCK_MS);
  }

  // --------------------------------------------------------------------- tabs
  function setTab(name) {
    state.tab = name;
    el.tabCapture.hidden = name !== 'capture';
    el.tabVault.hidden = name !== 'vault';
    el.navCapture.classList.toggle('on', name === 'capture');
    el.navVault.classList.toggle('on', name === 'vault');
    el.headerTitle.textContent = name === 'capture' ? 'Capture' : 'Vault';
    if (name === 'capture') {
      if (!state.captured) startCamera();
    } else {
      stopCamera(!!state.captured);
      loadList(true);
    }
  }

  // ------------------------------------------------------------------ camera
  function updateCamUi() {
    const reviewing = !!state.captured;
    el.camMsg.hidden = !!state.stream || reviewing;
    el.shutterBtn.disabled = !state.stream;
    el.ctrlLive.hidden = reviewing;
    el.ctrlReview.hidden = !reviewing;
    el.preview.classList.toggle('mirror', state.facing === 'user');
  }

  async function startCamera() {
    if (state.stream) return;
    const attempt = sessionEpoch;
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      el.camMsgText.textContent = 'Camera API unavailable. Open this page over HTTPS in Safari.';
      return updateCamUi();
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        audio: false,
        video: {
          facingMode: { ideal: state.facing },
          width: { ideal: 1920 },
          height: { ideal: 1080 }
        }
      });
      if (attempt !== sessionEpoch || !state.pass || state.tab !== 'capture' || state.captured) {
        stream.getTracks().forEach((t) => t.stop());   // user left meanwhile
        return;
      }
      state.stream = stream;
      el.video.srcObject = stream;
      await el.video.play();
      if (attempt !== sessionEpoch) return;
      drawLoop();
    } catch (e) {
      if (attempt !== sessionEpoch) return;
      state.stream = null;
      const denied = e && (e.name === 'NotAllowedError' || e.name === 'SecurityError');
      el.camMsgText.textContent = denied
        ? 'Camera access was denied. Allow it in iOS Settings, then tap Start Camera.'
        : 'Could not start the camera (' + (e && e.name ? e.name : 'error') + ').';
    }
    updateCamUi();
  }

  function drawLoop() {
    if (!state.stream) return;
    const v = el.video;
    if (v.readyState >= 2 && v.videoWidth) {
      if (el.preview.width !== v.videoWidth || el.preview.height !== v.videoHeight) {
        el.preview.width = v.videoWidth;
        el.preview.height = v.videoHeight;
      }
      pctx.drawImage(v, 0, 0);
    }
    state.raf = requestAnimationFrame(drawLoop);
  }

  function stopCamera(keepFrame) {
    cancelAnimationFrame(state.raf);
    if (state.stream) state.stream.getTracks().forEach((t) => t.stop());
    state.stream = null;
    el.video.srcObject = null;
    if (!keepFrame) clearPreview();
    updateCamUi();
  }

  function clearPreview() {
    el.preview.width = 2;
    el.preview.height = 2;
    pctx.clearRect(0, 0, 2, 2);
  }

  function wipeCapture() {
    state.captured = null;
    clearPreview();
    el.uploadBtn.textContent = 'Encrypt & Upload';
    el.uploadBtn.disabled = false;
    el.retakeBtn.disabled = false;
  }

  function snapshot() {
    const v = el.video;
    if (!state.stream || !v.videoWidth) return;
    const scale = Math.min(1, MAX_EDGE / Math.max(v.videoWidth, v.videoHeight));
    const w = Math.round(v.videoWidth * scale);
    const h = Math.round(v.videoHeight * scale);
    const off = document.createElement('canvas');
    off.width = w;
    off.height = h;
    off.getContext('2d').drawImage(v, 0, 0, w, h);
    state.captured = off.toDataURL('image/jpeg', JPEG_QUALITY);   // Base64, RAM only
    off.width = 0;
    off.height = 0;
    stopCamera(true);      // freeze the last frame on the preview canvas
  }

  async function retake() {
    wipeCapture();
    updateCamUi();
    await startCamera();
  }

  async function upload() {
    if (!state.captured || state.busy) return;
    const attempt = sessionEpoch;
    state.busy = true;
    el.uploadBtn.disabled = true;
    el.retakeBtn.disabled = true;
    try {
      el.uploadBtn.textContent = 'Encrypting…';
      const packed = await encryptText(state.captured);
      if (attempt !== sessionEpoch) return;
      el.uploadBtn.textContent = 'Uploading…';
      await api('upload', { data: packed });
      if (attempt !== sessionEpoch) return;
      toast('Encrypted and uploaded', 'ok');
      wipeCapture();
      state.busy = false;
      updateCamUi();
      startCamera();
    } catch (e) {
      if (attempt !== sessionEpoch) return;
      toast(friendly(e), 'err');
      el.uploadBtn.textContent = 'Encrypt & Upload';
      el.uploadBtn.disabled = false;
      el.retakeBtn.disabled = false;
    } finally {
      if (attempt === sessionEpoch) state.busy = false;
    }
  }

  // ------------------------------------------------------------------- vault
  async function loadList(silent) {
    if (!state.pass) return;
    const attempt = sessionEpoch;
    try {
      const r = await api('fetch_list');
      if (attempt !== sessionEpoch) return;
      state.items = r.files || [];
      renderList();
    } catch (e) {
      if (attempt === sessionEpoch && !silent) toast(friendly(e), 'err');
    }
  }

  function svgIcon(pathMarkup, cls) {
    const wrap = document.createElement('span');
    wrap.innerHTML = '<svg class="' + (cls || '') + '" viewBox="0 0 24 24">' + pathMarkup + '</svg>';   // static markup only
    return wrap.firstChild;
  }

  function renderList() {
    el.list.textContent = '';
    el.listEmpty.hidden = state.items.length > 0;
    el.list.hidden = state.items.length === 0;
    state.items.forEach((item) => {
      const row = document.createElement('button');
      row.type = 'button';
      row.className = 'item';

      const thumb = document.createElement('div');
      thumb.className = 'thumb';
      thumb.appendChild(svgIcon('<rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="10" r="1.5"/><path d="M4 18l5-5 4 4 3-3 4 4"/>'));

      const meta = document.createElement('div');
      meta.className = 'meta';
      const title = document.createElement('b');
      title.textContent = fmtDate(item.ts);
      const sub = document.createElement('span');
      sub.textContent = 'Encrypted · ' + (item.size / 1048576).toFixed(2) + ' MB';
      meta.appendChild(title);
      meta.appendChild(sub);

      row.appendChild(thumb);
      row.appendChild(meta);
      row.appendChild(svgIcon('<path d="M9 6l6 6-6 6"/>', 'chev'));
      row.addEventListener('click', () => openItem(item));
      el.list.appendChild(row);
    });
  }

  function drawToViewer(dataUrl, attempt) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => {
        if (attempt !== sessionEpoch || el.viewer.hidden) {
          img.onload = img.onerror = null;
          img.src = '';
          resolve();
          return;
        }
        const c = el.viewerCanvas;
        c.width = img.naturalWidth;
        c.height = img.naturalHeight;
        c.getContext('2d').drawImage(img, 0, 0);
        img.onload = img.onerror = null;
        img.src = '';
        resolve();
      };
      img.onerror = () => reject(new Error('Image could not be decoded'));
      img.src = dataUrl;
    });
  }

  async function openItem(item) {
    if (state.busy) return;
    const attempt = sessionEpoch;
    state.busy = true;
    el.viewer.hidden = false;
    el.viewerTitle.textContent = fmtDate(item.ts);
    el.viewerMsg.textContent = 'Downloading & decrypting…';
    el.viewerMsg.hidden = false;
    try {
      const r = await api('get_file', { id: item.id });
      if (attempt !== sessionEpoch) return;
      const dataUrl = await decryptText(r.data);
      if (attempt !== sessionEpoch || el.viewer.hidden) return;
      if (dataUrl.indexOf('data:image/') !== 0) throw new Error('File does not contain an image');
      await drawToViewer(dataUrl, attempt);
      if (attempt !== sessionEpoch || el.viewer.hidden) return;
      el.viewerMsg.hidden = true;
    } catch (e) {
      if (attempt !== sessionEpoch) return;
      el.viewerMsg.textContent = friendly(e);
      el.viewerMsg.hidden = false;
    } finally {
      if (attempt === sessionEpoch) state.busy = false;
    }
  }

  function closeViewer() {
    el.viewer.hidden = true;
    el.viewerCanvas.width = 2;
    el.viewerCanvas.height = 2;
    el.viewerCanvas.getContext('2d').clearRect(0, 0, 2, 2);
    el.viewerTitle.textContent = '';
  }

  // ------------------------------------------------------------------ events
  el.gateBtn.addEventListener('click', login);
  el.gatePass.addEventListener('keydown', (e) => { if (e.key === 'Enter') login(); });
  el.gateCancel.addEventListener('click', () => lock());
  el.gate.addEventListener('cancel', (e) => { e.preventDefault(); lock(); });
  el.calculator.addEventListener('click', (e) => {
    const button = e.target.closest('button[data-key]');
    if (button) pressCalculator(button.dataset.key);
  });
  document.addEventListener('keydown', (e) => {
    if (el.calculator.hidden || !el.gate.hidden || e.ctrlKey || e.metaKey || e.altKey) return;
    let key = e.key;
    if (key === 'Escape' || key === 'Delete') key = 'C';
    if (key === 'Enter') {
      // Let Enter activate a focused keypad button normally.
      if (e.target.closest && e.target.closest('button')) return;
      key = '=';
    }
    if (/^[0-9.+*/=\-%]$/.test(key) || key === 'C') {
      e.preventDefault();
      pressCalculator(key);
    }
  });
  el.lockBtn.addEventListener('click', () => lock('Locked.'));
  el.navCapture.addEventListener('click', () => setTab('capture'));
  el.navVault.addEventListener('click', () => setTab('vault'));
  el.camStart.addEventListener('click', startCamera);
  el.shutterBtn.addEventListener('click', snapshot);
  el.retakeBtn.addEventListener('click', retake);
  el.uploadBtn.addEventListener('click', upload);
  el.refreshBtn.addEventListener('click', () => loadList(false));
  el.viewerClose.addEventListener('click', closeViewer);
  el.flipBtn.addEventListener('click', () => {
    state.facing = state.facing === 'environment' ? 'user' : 'environment';
    stopCamera(false);
    startCamera();
  });

  // Block long-press / drag "save image" paths on canvases
  [el.preview, el.viewerCanvas].forEach((c) => {
    c.addEventListener('contextmenu', (e) => e.preventDefault());
    c.addEventListener('dragstart', (e) => e.preventDefault());
  });

  // Idle tracking
  ['pointerdown', 'touchstart', 'keydown'].forEach((evt) => {
    document.addEventListener(evt, () => { if (state.pass) armIdleTimer(); }, { passive: true });
  });

  // Background / foreground handling
  document.addEventListener('visibilitychange', () => {
    if (!state.pass) return;
    if (document.hidden) {
      closeViewer();
      stopCamera(!!state.captured);
      clearTimeout(hiddenTimer);
      hiddenTimer = setTimeout(() => lock('Locked after leaving the app.'), HIDDEN_LOCK_MS);
    } else {
      clearTimeout(hiddenTimer);
      armIdleTimer();
      if (state.tab === 'capture' && !state.captured) startCamera();
    }
  });
  window.addEventListener('pagehide', () => { if (state.pass) lock(); });

  // ------------------------------------------------------------ service worker
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('./sw.js').catch(() => { /* offline shell is optional */ });
    });
  }

  updateCamUi();
})();
