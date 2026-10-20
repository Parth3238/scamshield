// Browser-side checks for QR image uploads. The backend re-checks
// everything; this only saves the user a wasted upload.

export const QR_MAX_BYTES = 5 * 1024 * 1024; // 5 MB, same as the backend

export const QR_ACCEPTED_TYPES = ["image/png", "image/jpeg", "image/webp"];

const QR_ACCEPTED_EXTENSIONS = /\.(png|jpe?g|webp)$/i;

// Returns an error message, or null when the file looks fine.
export function validateQrFile(file: File): string | null {
  // Some browsers leave file.type empty; fall back to the extension.
  const typeOk =
    QR_ACCEPTED_TYPES.includes(file.type) ||
    QR_ACCEPTED_EXTENSIONS.test(file.name);
  if (!typeOk) {
    return "Please choose a PNG, JPEG or WEBP image.";
  }
  if (file.size === 0) {
    return "That file looks empty. Please choose another image.";
  }
  if (file.size > QR_MAX_BYTES) {
    return "The image is too large (max 5 MB). Please choose a smaller file.";
  }
  return null;
}
