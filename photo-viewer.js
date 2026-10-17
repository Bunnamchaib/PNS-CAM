'use strict';

class PhotoNavigator {
  constructor({ getItems, fetch, decode, draw, onLoading, onError, onIndex }) {
    Object.assign(this, { getItems, fetch, decode, draw, onLoading, onError, onIndex });
    this.generation = 0;
    this.id = null;
    this.cache = new Map();
  }

  current() { return this.getItems().find(item => item.id === this.id) || null; }

  packed(item) {
    if (!this.cache.has(item.id)) {
      const request = Promise.resolve().then(() => this.fetch(item));
      this.cache.set(item.id, request);
      request.catch(() => { if (this.cache.get(item.id) === request) this.cache.delete(item.id); });
    }
    return this.cache.get(item.id);
  }

  async open(index) {
    const items = this.getItems();
    if (index < 0 || index >= items.length) return;
    const item = items[index];
    this.id = item.id;
    const generation = ++this.generation;
    const valid = () => generation === this.generation && this.id === item.id;
    const neighbors = items.slice(Math.max(0, index - 1), index + 2);
    const keep = new Set(neighbors.map(record => record.id));
    for (const id of this.cache.keys()) if (!keep.has(id)) this.cache.delete(id);
    this.onIndex(index, items.length, item);
    this.onLoading('Downloading…');
    try {
      const packed = await this.packed(item);
      if (!valid()) return;
      this.onLoading('Decrypting…');
      const decoded = await this.decode(packed);
      if (!valid()) return;
      await this.draw(decoded, valid);
      if (!valid()) return;
      this.onLoading('');
      for (const neighbor of neighbors) {
        if (neighbor.id !== item.id) this.packed(neighbor).catch(() => {});
      }
    } catch (error) {
      if (!valid()) return;
      this.onLoading('');
      this.onError(error && error.message ? error.message : 'Could not load photo');
    }
  }

  move(step) {
    const index = this.getItems().findIndex(item => item.id === this.id);
    return index >= 0 ? this.open(index + step) : Promise.resolve();
  }

  close() {
    this.generation++;
    this.id = null;
    this.cache.clear();
    this.onLoading('');
  }
}

if (typeof module !== 'undefined' && module.exports) module.exports = { PhotoNavigator };
