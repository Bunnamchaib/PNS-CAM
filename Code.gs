/**
 * Secure Vault - Google Apps Script backend (container-bound to a Google Sheet)
 *
 * SETUP
 *  1. Open the Google Sheet > Extensions > Apps Script, paste this file.
 *  2. Project Settings (gear) > Script Properties > Add property:
 *        APP_PASSWORD = <a long, unique passphrase>
 *  3. Select function "setup" and click Run (authorise the requested scopes).
 *  4. Deploy > New deployment > Type: Web app
 *        Execute as: Me      Who has access: Anyone
 *     Copy the Web app URL that ends in /exec  (you type it into the PWA login).
 *  5. After changing code: Deploy > Manage deployments > Edit > New version.
 *
 * NOTE: Photos arrive already encrypted (AES-GCM) by the client. This script
 * refuses anything that is not an encrypted "v1" package.
 */

const CFG = {
  SHEET_NAME: 'VaultLog',
  FOLDER_NAME: 'SecureVault_Base64',
  MAX_FAILS: 5,
  LOCKOUT_SEC: 900,
  MAX_BODY_CHARS: 25 * 1024 * 1024,
  LIST_LIMIT: 300
};

const PACKED_RE = /^v1\.[A-Za-z0-9+\/=]+\.[A-Za-z0-9+\/=]+\.[A-Za-z0-9+\/=]+$/;
const ID_RE = /^[A-Za-z0-9_-]{10,128}$/;
const CLIENT_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const LOG_HEADERS = ['Timestamp', 'FileId', 'FileName', 'SizeChars', 'DeletedAt', 'ClientId'];

/** Run once from the editor: creates folder + log sheet and stores their IDs. */
function setup() {
  const props = PropertiesService.getScriptProperties();
  if (!props.getProperty('APP_PASSWORD')) {
    throw new Error('Add the Script Property APP_PASSWORD first (Project Settings).');
  }
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  props.setProperty('SHEET_ID', ss.getId());
  getSheet_();
  const folder = getFolder_();
  Logger.log('Ready. Vault folder: ' + folder.getUrl());
}

function doGet() {
  return json_({ ok: false, error: 'Not found' });
}

function doPost(e) {
  try {
    if (!e || !e.postData || !e.postData.contents) return json_({ ok: false, error: 'Bad request' });
    const body = e.postData.contents;
    if (body.length > CFG.MAX_BODY_CHARS) return json_({ ok: false, error: 'Payload too large' });

    let req;
    try { req = JSON.parse(body); } catch (_) { return json_({ ok: false, error: 'Bad request' }); }
    if (!req || typeof req !== 'object') return json_({ ok: false, error: 'Bad request' });

    const auth = authenticate_(req.password);
    if (!auth.ok) return json_({ ok: false, error: auth.error });

    switch (req.action) {
      case 'upload':     return upload_(req);
      case 'fetch_list': return fetchList_();
      case 'get_file':   return getFile_(req);
      case 'trash_file': return trashFile_(req);
      default:           return json_({ ok: false, error: 'Unknown action' });
    }
  } catch (err) {
    console.error(err && err.stack ? err.stack : err);
    return json_({ ok: false, error: 'Server error' });
  }
}

/* ------------------------------ actions ------------------------------ */

function upload_(req) {
  const data = req.data;
  if (typeof data !== 'string' || !PACKED_RE.test(data)) {
    return json_({ ok: false, error: 'Payload must be an encrypted v1 package' });
  }
  if (req.clientId !== undefined &&
      (typeof req.clientId !== 'string' || !CLIENT_ID_RE.test(req.clientId))) {
    return json_({ ok: false, error: 'Invalid client id' });
  }
  const clientId = req.clientId === undefined ? '' : req.clientId.toLowerCase();
  const lock = LockService.getScriptLock();
  lock.waitLock(15000);
  try {
    const sheet = getSheet_();
    if (clientId) {
      const existing = ledgerRows_(sheet).filter(function (row) {
        return row[1] && String(row[5]).toLowerCase() === clientId;
      })[0];
      // Acknowledge even a subsequently deleted upload: retries never resurrect it.
      if (existing) return json_({ ok: true, id: String(existing[1]), name: String(existing[2]), ts: timestamp_(existing[0]) });
    }
    const serverTime = Date.now();
    const validCapture = typeof req.capturedAt === 'number' && isFinite(req.capturedAt) &&
      req.capturedAt >= 0 && req.capturedAt <= serverTime + 5 * 60 * 1000;
    let now = new Date(validCapture ? req.capturedAt : serverTime);
    const name = clientId ? 'IMG_' + clientId + '.b64.txt' :
      'IMG_' + Utilities.formatDate(now, 'UTC', "yyyyMMdd'T'HHmmss'Z'") +
      '_' + Utilities.getUuid().slice(0, 6) + '.b64.txt';
    const folder = getFolder_();
    // If Drive succeeded but Sheets failed, recover the same file on the next retry.
    const matches = clientId ? folder.getFilesByName(name) : null;
    const file = matches && matches.hasNext() ? matches.next() : folder.createFile(name, data, MimeType.PLAIN_TEXT);
    if (!validCapture && clientId) now = file.getDateCreated();
    sheet.appendRow([now, file.getId(), name, data.length, file.isTrashed() ? new Date() : '', clientId]);
    return json_({ ok: true, id: file.getId(), name: name, ts: now.getTime() });
  } finally {
    lock.releaseLock();
  }
}

function fetchList_() {
  const sheet = getSheet_();
  const last = sheet.getLastRow();
  if (last < 2) return json_({ ok: true, files: [] });
  const rows = ledgerRows_(sheet);
  const files = rows
    .filter(function (r) { return r[1] && !r[4]; })
    .map(function (r) {
      const t = timestamp_(r[0]);
      return { ts: t, id: String(r[1]), name: String(r[2]), size: Number(r[3]) || 0 };
    })
    .sort(function (a, b) { return b.ts - a.ts; })
    .slice(0, CFG.LIST_LIMIT);
  return json_({ ok: true, files: files });
}

function getFile_(req) {
  const id = req.id;
  if (typeof id !== 'string' || !ID_RE.test(id)) return json_({ ok: false, error: 'Invalid file id' });

  let file;
  try { file = DriveApp.getFileById(id); } catch (_) { return json_({ ok: false, error: 'File not found' }); }

  // Only serve files that live inside the vault folder (never other Drive files).
  const vaultId = getFolder_().getId();
  let inVault = false;
  const parents = file.getParents();
  while (parents.hasNext()) {
    if (parents.next().getId() === vaultId) { inVault = true; break; }
  }
  if (!inVault || file.isTrashed()) return json_({ ok: false, error: 'File not found' });

  return json_({ ok: true, id: id, data: file.getBlob().getDataAsString('UTF-8') });
}

function trashFile_(req) {
  const id = req.id;
  if (typeof id !== 'string' || !ID_RE.test(id)) return json_({ ok: false, error: 'Invalid file id' });
  const lock = LockService.getScriptLock();
  lock.waitLock(15000);
  try {
    const sheet = getSheet_();
    const rows = ledgerRows_(sheet);
    const index = rows.findIndex(function (row) { return String(row[1]) === id; });
    if (index < 0) return json_({ ok: false, error: 'File not found' });
    let file;
    try { file = DriveApp.getFileById(id); } catch (_) { return json_({ ok: false, error: 'File not found' }); }
    const parents = file.getParents();
    const vaultId = getFolder_().getId();
    let inVault = false;
    while (parents.hasNext()) {
      if (parents.next().getId() === vaultId) { inVault = true; break; }
    }
    if (!inVault) return json_({ ok: false, error: 'File not found' });
    // Drive trash handles retention. Never permanently delete a vault file here.
    if (!file.isTrashed()) file.setTrashed(true);
    if (!rows[index][4]) sheet.getRange(index + 2, 5).setValue(new Date());
    return json_({ ok: true, id: id });
  } finally {
    lock.releaseLock();
  }
}

/* ------------------------------ security ------------------------------ */

function authenticate_(supplied) {
  const cache = CacheService.getScriptCache();
  const fails = parseInt(cache.get('fails') || '0', 10);
  if (fails >= CFG.MAX_FAILS) {
    return { ok: false, error: 'Too many failed attempts. Try again later.' };
  }
  const stored = PropertiesService.getScriptProperties().getProperty('APP_PASSWORD');
  if (!stored) {
    return { ok: false, error: 'Server not configured: set APP_PASSWORD in Script Properties.' };
  }
  if (typeof supplied !== 'string' || !safeEqual_(supplied, stored)) {
    cache.put('fails', String(fails + 1), CFG.LOCKOUT_SEC);
    Utilities.sleep(800);
    return { ok: false, error: 'Invalid credentials' };
  }
  cache.remove('fails');
  return { ok: true };
}

function safeEqual_(a, b) {
  a = String(a); b = String(b);
  let diff = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

/* ------------------------------ helpers ------------------------------ */

function getFolder_() {
  const props = PropertiesService.getScriptProperties();
  const id = props.getProperty('FOLDER_ID');
  if (id) {
    try {
      const f = DriveApp.getFolderById(id);
      if (!f.isTrashed()) return f;
    } catch (_) { /* recreate below */ }
  }
  const folder = DriveApp.createFolder(CFG.FOLDER_NAME);
  props.setProperty('FOLDER_ID', folder.getId());
  return folder;
}

function getSheet_() {
  const props = PropertiesService.getScriptProperties();
  const sid = props.getProperty('SHEET_ID');
  const ss = sid ? SpreadsheetApp.openById(sid) : SpreadsheetApp.getActiveSpreadsheet();
  let sh = ss.getSheetByName(CFG.SHEET_NAME);
  if (!sh) {
    sh = ss.insertSheet(CFG.SHEET_NAME);
    sh.appendRow(LOG_HEADERS);
    sh.setFrozenRows(1);
  } else {
    // Extend the old four-column ledger in place; legacy rows read as empty cells.
    const extra = sh.getRange(1, 5, 1, 2).getValues()[0];
    if (extra[0] !== LOG_HEADERS[4] || extra[1] !== LOG_HEADERS[5]) {
      sh.getRange(1, 5, 1, 2).setValues([[LOG_HEADERS[4], LOG_HEADERS[5]]]);
    }
  }
  return sh;
}

function ledgerRows_(sheet) {
  const last = sheet.getLastRow();
  return last < 2 ? [] : sheet.getRange(2, 1, last - 1, LOG_HEADERS.length).getValues();
}

function timestamp_(value) {
  return value instanceof Date ? value.getTime() : new Date(value).getTime();
}

function json_(obj) {
  return ContentService.createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}
