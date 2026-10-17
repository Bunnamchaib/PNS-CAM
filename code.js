/* Secure Vault - client logic.
 * Passwords/decrypted images remain in RAM. Only encrypted pending uploads
 * persist in IndexedDB until server acknowledgement. */
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
    encoding: 0,
    items: [],
    tab: 'capture',
    busy: false
  };
  let idleTimer = 0;
  let hiddenTimer = 0;
  let toastTimer = 0;
  let sessionEpoch = 0;
  const calculator = new Calculator();
  const unsaved = new Map();
  let queueState = { pending: 0, sending: false, error: null };
  let captureError = '';
  let deleting = false;
  let swipeStart = null;
  let listRevision = 0;
  let listRequest = 0;
  let importing = false;
  let importProgress = '';
  let pickerEpoch = null;
  let exportFile = null;
  let exportId = null;
  let sharing = false;
  const downloadUrls = new Map();

  // ---------------------------------------------------------------- elements
  const el = {};
  [
    'calculator', 'calcDisplay', 'calcExpression', 'calcClear', 'gate', 'gateCancel', 'gatePass', 'gateBtn', 'gateMsg', 'app', 'headerTitle', 'lockBtn',
    'tabCapture', 'tabVault', 'navCapture', 'navVault', 'preview', 'video', 'camMsg',
    'camMsgText', 'camStart', 'flipBtn', 'shutterBtn', 'queueStatus', 'queueRetry', 'importBtn', 'vaultImportBtn', 'importInput',
    'ctrlLive', 'refreshBtn', 'list', 'listEmpty', 'viewer', 'viewerCanvas',
    'viewerClose', 'viewerMsg', 'viewerTitle', 'viewerLoading', 'viewerStage', 'viewerPrev', 'viewerNext', 'viewerCount', 'viewerDelete',
    'trashDialog', 'trashConfirm', 'trashCancel', 'trashMsg', 'viewerShare', 'exportDialog', 'shareApps', 'saveImage', 'exportCancel', 'exportHint', 'toast'
  ].forEach((id) => { el[id] = document.getElementById(id); });
  const pctx = el.preview.getContext('2d');
  const uploadQueue = new UploadQueue({
    store: new IndexedDbQueueStore(), endpoint: BACKEND_URL,
    send: async (record) => {
      if (!state.pass) throw new Error('Unlock to resume uploads');
      const attempt = sessionEpoch;
      const result = await api('upload', { data: record.data, clientId: record.id, capturedAt: record.createdAt });
      if (attempt === sessionEpoch && state.pass && !state.items.some(item => item.id === result.id)) {
        listRevision++;
        state.items.unshift({ id: result.id, name: result.name, ts: result.ts, size: record.data.length });
        state.items.sort((a, b) => b.ts - a.ts);
        renderList();
      }
      return result;
    },
    onChange: (status) => { queueState = status; updateQueueUi(); }
  });
  const photoViewer = new PhotoNavigator({
    getItems: () => state.items,
    fetch: async (item) => (await api('get_file', { id: item.id })).data,
    decode: decryptText, draw: drawToViewer,
    onIndex: (index, total, item) => {
      clearExport();
      el.viewerTitle.textContent = fmtDate(item.ts);
      el.viewerCount.textContent = (index + 1) + ' / ' + total;
      el.viewerPrev.disabled = index === 0;
      el.viewerNext.disabled = index === total - 1;
      el.viewerMsg.hidden = true;
      el.viewerCanvas.width = 2; el.viewerCanvas.height = 2;
    },
    onLoading: (phase) => {
      el.viewerLoading.hidden = !phase;
      el.viewerDelete.disabled = !!phase || deleting;
      el.viewerShare.disabled = !!phase || deleting || !exportFile;
      if (phase) { el.viewerMsg.textContent = phase; el.viewerMsg.hidden = false; }
      else el.viewerMsg.hidden = true;
    },
    onError: (message) => { el.viewerMsg.textContent = message; el.viewerMsg.hidden = false; }
  });

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
  async function encryptText(plain, password = state.pass) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKey(password, salt, 'encrypt');
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
      listRevision++;
      el.gatePass.value = '';
      showApp();
      renderList();
      uploadQueue.start();
      retryUnsaved();
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
    pickerEpoch = null;
    el.importInput.value = '';
    uploadQueue.pause();
    stopCamera(false);
    closeViewer();
    state.url = null;
    state.pass = null;
    state.items = [];
    state.busy = false;
    deleting = false;
    el.trashDialog.close();
    el.trashDialog.hidden = true;
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
    el.calculator.querySelectorAll('.operator').forEach((button) => button.classList.remove('selected'));
    clearTimeout(idleTimer);
    clearTimeout(hiddenTimer);
    gateMessage('');
    el.calcClear.focus();
  }

  function pressCalculator(key) {
    const result = calculator.press(key);
    el.calcDisplay.textContent = result.display;
    el.calcExpression.textContent = result.expression.replace(/\*/g, '×').replace(/\//g, '÷');
    el.calculator.querySelectorAll('.operator').forEach((button) => {
      button.classList.toggle('selected', button.dataset.key !== '=' && result.expression.endsWith(' ' + button.dataset.key));
    });
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
      startCamera();
    } else {
      stopCamera();
      loadList(true);
    }
  }

  // ------------------------------------------------------------------ camera
  function updateCamUi() {
    el.camMsg.hidden = !!state.stream;
    el.shutterBtn.disabled = !state.stream || state.encoding >= 8;
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
      if (attempt !== sessionEpoch || !state.pass || state.tab !== 'capture') {
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

  function stopCamera() {
    cancelAnimationFrame(state.raf);
    if (state.stream) state.stream.getTracks().forEach((t) => t.stop());
    state.stream = null;
    el.video.srcObject = null;
    clearPreview();
    updateCamUi();
  }

  function clearPreview() {
    el.preview.width = 2;
    el.preview.height = 2;
    pctx.clearRect(0, 0, 2, 2);
  }

  function updateQueueUi() {
    const pending = queueState.pending + unsaved.size;
    el.queueStatus.textContent = importProgress || captureError || (unsaved.size ? 'Device storage error · ' + unsaved.size + ' waiting to save' :
      queueState.error ? 'Upload paused · ' + pending + ' saved on this device' :
      state.encoding ? 'Saving ' + state.encoding + ' · ' + pending + ' queued' :
      pending ? (queueState.sending ? 'Uploading · ' : 'Waiting · ') + pending + ' remaining' : 'All photos uploaded');
    el.queueRetry.hidden = !queueState.error && !unsaved.size && !captureError;
  }

  async function retryUnsaved() {
    captureError = '';
    for (const [id, record] of unsaved) {
      try { await uploadQueue.enqueue(record); unsaved.delete(id); }
      catch (_) { break; }
    }
    uploadQueue.retry();
    updateQueueUi();
  }

  function snapshot() {
    const v = el.video;
    if (!state.stream || !v.videoWidth || !state.pass || state.encoding >= 8) return;
    const password = state.pass;
    const id = crypto.randomUUID(), createdAt = Date.now();
    const scale = Math.min(1, MAX_EDGE / Math.max(v.videoWidth, v.videoHeight));
    const off = document.createElement('canvas');
    off.width = Math.round(v.videoWidth * scale);
    off.height = Math.round(v.videoHeight * scale);
    off.getContext('2d').drawImage(v, 0, 0, off.width, off.height);
    state.encoding++;
    captureError = '';
    updateCamUi(); updateQueueUi();
    // Each shutter press owns its frame; no encoding or persistence waits on network.
    const blob = new Promise((resolve, reject) => off.toBlob(value => value ? resolve(value) : reject(new Error('Could not encode photo')), 'image/jpeg', JPEG_QUALITY));
    void saveCaptured(blob, password, id, createdAt).finally(() => { off.width = 0; off.height = 0; });
  }

  async function saveCaptured(blobPromise, password, id, createdAt) {
    let record;
    try {
      const blob = await blobPromise;
      const plain = 'data:image/jpeg;base64,' + bytesToB64(new Uint8Array(await blob.arrayBuffer()));
      const data = await encryptText(plain, password);
      record = { id, createdAt, endpoint: BACKEND_URL, data };
      // Finishing after Lock is safe: the paused queue persists only ciphertext.
      await uploadQueue.enqueue(record);
      return true;
    } catch (e) {
      if (record) unsaved.set(id, record);
      else captureError = 'Photo was not saved. Please take it again.';
      return false;
    } finally {
      state.encoding--;
      updateCamUi(); updateQueueUi();
    }
  }

  function choosePhotos() {
    if (!state.pass || importing) return;
    pickerEpoch = sessionEpoch;
    el.importInput.click();
  }

  async function importPhotos() {
    const files = Array.from(el.importInput.files || []);
    el.importInput.value = '';
    const attempt = pickerEpoch;
    pickerEpoch = null;
    if (!state.pass || attempt !== sessionEpoch || importing || !files.length) return;
    const password = state.pass;
    importing = true;
    el.importBtn.disabled = el.vaultImportBtn.disabled = true;
    let added = 0, failed = 0, storageStopped = false;
    try {
      for (let index = 0; index < files.length; index++) {
        if (attempt !== sessionEpoch) break;
        importProgress = 'Importing ' + (index + 1) + ' / ' + files.length;
        updateQueueUi();
        try {
          const blob = await PhotoIO.imageFileToJpeg(files[index]);
          if (attempt !== sessionEpoch) break;
          state.encoding++;
          updateCamUi();
          if (await saveCaptured(Promise.resolve(blob), password, crypto.randomUUID(), Date.now())) added++;
          else { failed++; storageStopped = true; break; }
        } catch (_) { failed++; }
      }
      if (attempt === sessionEpoch) {
        toast(storageStopped ? 'Import stopped: device storage is unavailable. Use Retry, then select the remaining photos.' :
          failed ? 'Added ' + added + ' photos. ' + failed + ' could not be imported.' : 'Added ' + added + ' photos', failed ? 'err' : 'ok');
      }
    } finally {
      importing = false;
      importProgress = '';
      el.importBtn.disabled = el.vaultImportBtn.disabled = false;
      updateQueueUi();
    }
  }

  // ------------------------------------------------------------------- vault
  async function loadList(silent) {
    if (!state.pass) return;
    const attempt = sessionEpoch;
    const revision = listRevision;
    const request = ++listRequest;
    try {
      const r = await api('fetch_list');
      if (attempt !== sessionEpoch || revision !== listRevision || request !== listRequest) return;
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

  function drawToViewer(dataUrl, valid) {
    return new Promise((resolve, reject) => {
      if (typeof dataUrl !== 'string' || !dataUrl.startsWith('data:image/')) { reject(new Error('File does not contain an image')); return; }
      const img = new Image();
      img.onload = () => {
        try {
          if (valid() && !el.viewer.hidden) {
            const c = el.viewerCanvas;
            c.width = img.naturalWidth; c.height = img.naturalHeight;
            c.getContext('2d').drawImage(img, 0, 0);
            const item = photoViewer.current();
            const name = 'photo-' + new Date(item.ts).toISOString().replace(/[^0-9T]/g, '');
            if (/^data:image\/jpeg;base64,/i.test(dataUrl)) {
              exportFile = PhotoIO.fileFromDataUrl(dataUrl, name);
              exportId = item.id;
            } else {
              c.toBlob(blob => {
                if (blob && valid() && !el.viewer.hidden) {
                  exportFile = new File([blob], name + '.jpg', { type: 'image/jpeg' });
                  exportId = item.id;
                }
                resolve();
              }, 'image/jpeg', 0.95);
              img.onload = img.onerror = null; img.src = ''; return;
            }
          }
          resolve();
        } catch (error) { reject(error); }
        finally { img.onload = img.onerror = null; img.src = ''; }
      };
      img.onerror = () => reject(new Error('Image could not be decoded'));
      img.src = dataUrl;
    });
  }

  async function openItem(item) {
    if (!state.pass || deleting) return;
    el.viewer.hidden = false;
    await photoViewer.open(state.items.findIndex(record => record.id === item.id));
  }

  function closeViewer() {
    clearExport();
    photoViewer.close(); swipeStart = null;
    el.viewer.hidden = true;
    el.viewerCanvas.width = 2; el.viewerCanvas.height = 2;
    el.viewerCanvas.getContext('2d').clearRect(0, 0, 2, 2);
    el.viewerTitle.textContent = '';
  }

  function closeExportMenu() {
    el.exportDialog.close();
    el.exportDialog.hidden = true;
  }

  function clearExport() {
    closeExportMenu();
    exportFile = null; exportId = null; sharing = false;
    el.viewerShare.disabled = true;
    for (const [url, timer] of downloadUrls) {
      clearTimeout(timer); URL.revokeObjectURL(url);
    }
    downloadUrls.clear();
  }

  function currentExport() {
    return state.pass && !el.viewer.hidden && exportFile && photoViewer.current()?.id === exportId ? exportFile : null;
  }

  function openExportMenu() {
    const file = currentExport();
    if (!file || sharing) return;
    el.shareApps.disabled = !PhotoIO.canShareFile(file, navigator);
    el.exportHint.textContent = el.shareApps.disabled ? 'File sharing is unavailable in this browser. Use Save image, then share from your device.' :
      'Choose an app in your device’s share menu, or save a JPG. On iPhone, use the system menu to save to Photos.';
    el.exportDialog.hidden = false; el.exportDialog.showModal();
  }

  async function shareToApps() {
    const file = currentExport();
    if (!file || sharing || !PhotoIO.canShareFile(file, navigator)) return;
    const attempt = sessionEpoch;
    sharing = true;
    closeExportMenu();
    try {
      // File was prepared while loading the image: invoke share in this click.
      await PhotoIO.shareFile(file, navigator);
    } catch (error) {
      if (attempt === sessionEpoch && error.name !== 'AbortError') toast('Could not share. Try Save image instead.', 'err');
    } finally {
      if (attempt === sessionEpoch) sharing = false;
    }
  }

  function saveImage() {
    const file = currentExport();
    if (!file) return;
    const url = URL.createObjectURL(file);
    const link = document.createElement('a');
    link.href = url; link.download = file.name; link.rel = 'noopener';
    document.body.appendChild(link); link.click(); link.remove();
    const timer = setTimeout(() => { URL.revokeObjectURL(url); downloadUrls.delete(url); }, 60000);
    downloadUrls.set(url, timer);
    closeExportMenu();
  }

  function askTrash() {
    if (!photoViewer.current() || deleting) return;
    el.trashMsg.textContent = '';
    el.trashConfirm.disabled = false; el.trashCancel.disabled = false;
    el.trashDialog.hidden = false; el.trashDialog.showModal();
  }

  function cancelTrash() {
    if (deleting) return;
    el.trashDialog.close(); el.trashDialog.hidden = true;
  }

  async function confirmTrash() {
    const item = photoViewer.current();
    if (!item || deleting || !state.pass) return;
    const attempt = sessionEpoch;
    const index = state.items.findIndex(record => record.id === item.id);
    deleting = true;
    el.trashConfirm.disabled = true; el.trashCancel.disabled = true;
    el.trashMsg.textContent = 'Moving to trash…';
    try {
      await api('trash_file', { id: item.id });
      if (attempt !== sessionEpoch) return;
      photoViewer.close();
      listRevision++;
      state.items = state.items.filter(record => record.id !== item.id);
      renderList(); deleting = false; cancelTrash();
      if (state.items.length) await photoViewer.open(Math.min(index, state.items.length - 1));
      else closeViewer();
    } catch (e) {
      if (attempt === sessionEpoch) el.trashMsg.textContent = friendly(e);
    } finally {
      if (attempt === sessionEpoch) {
        deleting = false; el.trashConfirm.disabled = false; el.trashCancel.disabled = false;
      }
    }
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
  el.importBtn.addEventListener('click', choosePhotos);
  el.vaultImportBtn.addEventListener('click', choosePhotos);
  el.importInput.addEventListener('change', importPhotos);
  el.importInput.addEventListener('cancel', () => { pickerEpoch = null; });
  el.queueRetry.addEventListener('click', retryUnsaved);
  el.refreshBtn.addEventListener('click', () => loadList(false));
  el.viewerClose.addEventListener('click', closeViewer);
  el.viewerPrev.addEventListener('click', () => photoViewer.move(-1));
  el.viewerNext.addEventListener('click', () => photoViewer.move(1));
  el.viewerDelete.addEventListener('click', askTrash);
  el.viewerShare.addEventListener('click', openExportMenu);
  el.shareApps.addEventListener('click', shareToApps);
  el.saveImage.addEventListener('click', saveImage);
  el.exportCancel.addEventListener('click', closeExportMenu);
  el.exportDialog.addEventListener('cancel', (e) => { e.preventDefault(); closeExportMenu(); });
  el.trashCancel.addEventListener('click', cancelTrash);
  el.trashConfirm.addEventListener('click', confirmTrash);
  el.trashDialog.addEventListener('cancel', (e) => { e.preventDefault(); cancelTrash(); });
  el.viewerStage.addEventListener('touchstart', (e) => {
    const touch = e.touches[0];
    swipeStart = touch ? { x: touch.clientX, y: touch.clientY } : null;
  }, { passive: true });
  el.viewerStage.addEventListener('touchend', (e) => {
    const touch = e.changedTouches[0], start = swipeStart;
    swipeStart = null;
    if (!touch || !start || deleting) return;
    const dx = touch.clientX - start.x, dy = touch.clientY - start.y;
    if (Math.abs(dx) > 45 && Math.abs(dx) > Math.abs(dy) * 1.3) photoViewer.move(dx < 0 ? 1 : -1);
  }, { passive: true });
  document.addEventListener('keydown', (e) => {
    if (el.viewer.hidden || !el.trashDialog.hidden || !el.exportDialog.hidden) return;
    if (e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
      e.preventDefault(); photoViewer.move(e.key === 'ArrowLeft' ? -1 : 1);
    }
    if (e.key === 'Escape') closeViewer();
  });
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
      stopCamera();
      clearTimeout(hiddenTimer);
      hiddenTimer = setTimeout(() => lock('Locked after leaving the app.'), HIDDEN_LOCK_MS);
    } else {
      clearTimeout(hiddenTimer);
      armIdleTimer();
      if (state.tab === 'capture') startCamera();
      uploadQueue.retry();
    }
  });
  window.addEventListener('pagehide', () => { if (state.pass) lock(); });
  window.addEventListener('online', () => { if (state.pass) retryUnsaved(); });

  // ------------------------------------------------------------ service worker
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', () => {
      navigator.serviceWorker.register('./sw.js').catch(() => { /* offline shell is optional */ });
    });
  }

  updateCamUi();
})();
