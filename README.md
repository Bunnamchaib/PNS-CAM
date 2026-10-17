# PNS-CAM

Open https://bunnamchaib.github.io/PNS-CAM/ as Calculator. Enter `AC`, `1`, `+`, `1`, `=` to open password entry. The existing Apps Script endpoint is configured in `code.js`; the password is never embedded or persisted.

## Capture

Tap the shutter to keep taking photos while earlier captures upload. Photos are converted to JPEG/Base64, encrypted with AES-GCM, and saved to a temporary IndexedDB queue before upload. Only acknowledged uploads are removed. Network failures retry automatically; failed device writes show a Retry action. Lock pauses new uploads; unlock resumes the queue. iOS may suspend background pages, so uploads can pause until the app is reopened and unlocked.

## Viewing and deletion

Use Import in Capture or Vault to select multiple gallery photos. Images are converted to JPEG and enter the same encrypted upload queue; camera permission is not required to import. Unsupported image formats show an import failure while other selected photos continue.

For a loaded photo, Share / Save opens one action menu. Share to apps opens the device share sheet for installed apps. Save image downloads a JPG; on iPhone, use the system sharing menu to save into Photos. Native file sharing availability depends on the device/browser. Cancelling a share does not automatically download the image. Export files are prepared only for the displayed photo and cleared from the app on navigation/close/lock.

Swipe horizontally or use Previous/Next to browse. A loading bar indicates downloading/decrypting. Delete requires confirmation and moves the file to Google Drive trash, where Google applies its 30-day retention. This app never permanently deletes Drive files.

## Backend updates

The root `Code.gs` is the backend source. Copy it into the existing container-bound Apps Script project and update the existing Web app deployment with a new version to preserve the `/exec` URL. Keep `APP_PASSWORD`, `SHEET_ID`, and `FOLDER_ID` Script Properties. Existing four-column VaultLog rows remain supported; the backend adds DeletedAt and ClientId columns for trash and idempotent uploads.

Frontend files are served from the repository root by GitHub Pages. `sw.js` caches static app files only; photo requests and passwords are not cached by the service worker.
