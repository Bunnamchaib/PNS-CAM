(function (root, factory) {
    'use strict';
    const api = factory(root);
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.PhotoIO = api;
})(typeof globalThis !== 'undefined' ? globalThis : this, function (root) {
    'use strict';

    // Browser dependencies can be injected to exercise decode and cleanup failures.
    async function imageFileToJpeg(file, platform = {}) {
        const type = file && typeof file.type === 'string' ? file.type.toLowerCase() : '';
        const hasImageName = file && /\.(jpe?g|png|gif|webp|bmp|avif|heic|heif|tiff?|ico|svg)$/i.test(file.name || '');
        if (!file || typeof file.arrayBuffer !== 'function' || (type ? !/^image\/[a-z0-9.+-]+$/.test(type) : !hasImageName)) {
            throw new Error('Please select an image file.');
        }
        const urlApi = platform.URL || root.URL;
        const createImage = platform.createImage || (() => new root.Image());
        const createCanvas = platform.createCanvas || (() => root.document.createElement('canvas'));
        let url, image, canvas;
        try {
            image = createImage();
            canvas = createCanvas();
            url = urlApi.createObjectURL(file);
            await new Promise((resolve, reject) => {
                image.onload = resolve;
                image.onerror = () => reject(new Error('Unable to decode image file.'));
                image.src = url;
            });
            const width = image.naturalWidth;
            const height = image.naturalHeight;
            if (!Number.isFinite(width) || !Number.isFinite(height) || width <= 0 || height <= 0) {
                throw new Error('Invalid image dimensions.');
            }
            const scale = Math.min(1, 1600 / Math.max(width, height));
            canvas.width = Math.max(1, Math.round(width * scale));
            canvas.height = Math.max(1, Math.round(height * scale));
            const context = canvas.getContext('2d');
            if (!context) throw new Error('Unable to prepare image canvas.');
            context.drawImage(image, 0, 0, canvas.width, canvas.height);
            return await new Promise((resolve, reject) => {
                canvas.toBlob(blob => blob ? resolve(blob) : reject(new Error('Unable to encode image.')), 'image/jpeg', 0.85);
            });
        } finally {
            if (image) {
                image.onload = null;
                image.onerror = null;
                image.removeAttribute('src');
            }
            if (url !== undefined) urlApi.revokeObjectURL(url);
            if (canvas) {
                canvas.width = 0;
                canvas.height = 0;
            }
        }
    }

    const extensions = {
        'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp',
        'image/gif': 'gif', 'image/bmp': 'bmp', 'image/avif': 'avif',
        'image/heic': 'heic', 'image/heif': 'heif', 'image/tiff': 'tiff',
        'image/svg+xml': 'svg', 'image/x-icon': 'ico', 'image/vnd.microsoft.icon': 'ico'
    };

    function fileFromDataUrl(dataUrl, baseName = 'photo') {
        const match = typeof dataUrl === 'string' && /^data:(image\/[a-z0-9.+-]+);base64,([a-z0-9+/]*={0,2})$/i.exec(dataUrl);
        if (!match || !match[2] || match[2].length % 4 === 1 || (match[2].includes('=') && match[2].length % 4 !== 0)) {
            throw new Error('Invalid image data URL.');
        }
        const mime = match[1].toLowerCase();
        const extension = extensions[mime];
        if (!extension) throw new Error('Unsupported image data URL type.');
        let decoded;
        try { decoded = root.atob(match[2]); }
        catch (_) { throw new Error('Invalid image data URL base64.'); }
        const bytes = Uint8Array.from(decoded, character => character.charCodeAt(0));
        const name = String(baseName || 'photo').split(/[\\/]/).pop().replace(/\.[^.]*$/, '').replace(/[\x00-\x1f<>:"|?*]/g, '_') || 'photo';
        return new root.File([bytes], name + '.' + extension, { type: mime });
    }

    function canShareFile(file, navigatorArg = root.navigator) {
        try {
            return !!(file && navigatorArg && typeof navigatorArg.share === 'function' &&
                typeof navigatorArg.canShare === 'function' && navigatorArg.canShare({ files: [file] }));
        } catch (_) { return false; }
    }

    // Invoke share before returning so the click's transient activation is retained.
    function shareFile(file, navigatorArg = root.navigator) {
        try {
            if (!file || !navigatorArg || typeof navigatorArg.share !== 'function') {
                return Promise.reject(new Error('File sharing is not supported.'));
            }
            return Promise.resolve(navigatorArg.share({ files: [file] }));
        } catch (error) { return Promise.reject(error); }
    }

    return { imageFileToJpeg, fileFromDataUrl, canShareFile, shareFile };
});
