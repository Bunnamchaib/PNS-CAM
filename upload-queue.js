(function (root) {
  'use strict';

  // Persist only the encrypted package and routing/idempotency metadata.
  function queueRecord(record) {
    if (!record || typeof record.data !== 'string' || !/^v1\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+\.[A-Za-z0-9+/=]+$/.test(record.data)) {
      throw new Error('Queue accepts encrypted v1 packages only');
    }
    if (typeof record.id !== 'string' || !record.id || typeof record.endpoint !== 'string' || !record.endpoint || !Number.isFinite(record.createdAt)) {
      throw new Error('Invalid queue metadata');
    }
    return { id: record.id, data: record.data, createdAt: record.createdAt, endpoint: record.endpoint };
  }

  class IndexedDbQueueStore {
    constructor({ name = 'b64photohub-upload-queue', indexedDB = root.indexedDB } = {}) {
      this.name = name;
      this.indexedDB = indexedDB;
      this.database = null;
    }

    _open() {
      if (!this.database) {
        this.database = new Promise((resolve, reject) => {
          if (!this.indexedDB) { reject(new Error('IndexedDB is unavailable')); return; }
          const request = this.indexedDB.open(this.name, 1);
          request.onupgradeneeded = () => {
            const store = request.result.createObjectStore('uploads', { keyPath: 'id' });
            store.createIndex('endpoint', 'endpoint', { unique: false });
          };
          request.onerror = () => reject(request.error || new Error('Could not open upload queue'));
          request.onsuccess = () => {
            const db = request.result;
            db.onversionchange = () => { db.close(); this.database = null; };
            resolve(db);
          };
        }).catch(error => { this.database = null; throw error; });
      }
      return this.database;
    }

    async _transaction(mode, operation) {
      const db = await this._open();
      return new Promise((resolve, reject) => {
        const transaction = db.transaction('uploads', mode);
        let request;
        transaction.oncomplete = () => resolve(request.result);
        transaction.onabort = transaction.onerror = () => reject(transaction.error || new Error('Upload queue transaction failed'));
        try { request = operation(transaction.objectStore('uploads')); }
        catch (error) { transaction.abort(); reject(error); }
      });
    }

    async put(record) {
      const safe = queueRecord(record);
      // The transaction completion, not the request success, marks durable enqueue.
      await this._transaction('readwrite', store => store.put(safe));
    }

    async list(endpoint) {
      const records = await this._transaction('readonly', store => store.index('endpoint').getAll(endpoint));
      return records.sort((a, b) => a.createdAt - b.createdAt || a.id.localeCompare(b.id));
    }

    async remove(id) {
      await this._transaction('readwrite', store => store.delete(id));
    }
  }

  class UploadQueue {
    constructor({ store, send, endpoint, onChange = () => {}, setTimeout = root.setTimeout.bind(root), clearTimeout = root.clearTimeout.bind(root) }) {
      this.store = store;
      this.send = send;
      this.endpoint = endpoint;
      this.onChange = onChange;
      this.setTimer = setTimeout;
      this.clearTimer = clearTimeout;
      this.active = false;
      this.running = false;
      this.wake = false;
      this.timer = null;
      this.failures = 0;
      this.revision = 0;
      this.state = { pending: 0, sending: false, error: null };
      void this._refresh();
    }

    status() { return { ...this.state }; }

    _notify() {
      try { this.onChange(this.status()); } catch (_) { /* UI must not stop durable work. */ }
    }

    async _refresh() {
      const revision = ++this.revision;
      try {
        const records = await this.store.list(this.endpoint);
        if (revision === this.revision) { this.state.pending = records.length; this._notify(); }
      } catch (error) {
        if (revision === this.revision) { this.state.error = error.message || String(error); this._notify(); }
      }
    }

    async enqueue(record) {
      const safe = queueRecord(record);
      if (safe.endpoint !== this.endpoint) throw new Error('Queue endpoint mismatch');
      await this.store.put(safe);
      await this._refresh();
      this._kick();
      return safe.id;
    }

    start() { this.active = true; this._kick(); }

    pause() {
      this.active = false;
      this.wake = false;
      if (this.timer !== null) this.clearTimer(this.timer);
      this.timer = null;
    }

    retry() {
      if (this.timer !== null) this.clearTimer(this.timer);
      this.timer = null;
      this._kick();
    }

    _kick() {
      if (!this.active || this.timer !== null) return;
      if (this.running) { this.wake = true; return; }
      this.running = true;
      this.wake = false;
      const run = () => this._drain();
      const locks = root.navigator && root.navigator.locks;
      // This lock coordinates tabs; the server's idempotency key also covers
      // retries after acknowledgement loss and browsers without Web Locks.
      const work = locks ? locks.request('b64photohub-upload:' + this.endpoint, run) : run();
      Promise.resolve(work).catch(error => this._failed(error)).finally(() => {
        this.running = false;
        if (this.wake) this._kick();
      });
    }

    _failed(error) {
      this.state.sending = false;
      this.state.error = error.message || String(error);
      this._notify();
      if (!this.active) return;
      const delay = Math.min(30000, 1000 * Math.pow(2, Math.min(this.failures++, 5)));
      this.timer = this.setTimer(() => { this.timer = null; this._kick(); }, delay);
    }

    async _drain() {
      while (this.active) {
        const records = await this.store.list(this.endpoint);
        ++this.revision;
        this.state.pending = records.length;
        this._notify();
        if (!this.active || !records.length) return;
        const record = records[0];
        this.state.sending = true;
        this.state.error = null;
        this._notify();
        await this.send(record);
        // An in-flight acknowledged upload may be cleaned up after pause.
        // Any failure before transaction completion leaves the record retryable.
        await this.store.remove(record.id);
        this.state.sending = false;
        this.state.error = null;
        this.failures = 0;
        await this._refresh();
      }
    }
  }

  root.IndexedDbQueueStore = IndexedDbQueueStore;
  root.UploadQueue = UploadQueue;
  if (typeof module !== 'undefined' && module.exports) module.exports = { IndexedDbQueueStore, UploadQueue };
})(typeof globalThis !== 'undefined' ? globalThis : this);
