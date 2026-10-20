"use client";

import { useRouter } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { ApiError, postScanQr } from "@/lib/api";
import { validateQrFile } from "@/lib/qrfile";

// QR image picker: file input plus drag and drop, with a small preview.
export default function QrUpload() {
  const router = useRouter();
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  // Holds the live preview URL so it can be revoked on replace/unmount.
  const urlRef = useRef<string | null>(null);

  // Revoke the preview URL on unmount; it is temporary by design.
  useEffect(() => {
    const ref = urlRef;
    return () => {
      if (ref.current !== null) {
        URL.revokeObjectURL(ref.current);
      }
    };
  }, []);

  function pick(chosen: File | undefined) {
    if (!chosen) {
      return;
    }
    const problem = validateQrFile(chosen);
    if (problem !== null) {
      setError(problem);
      return;
    }
    setError(null);
    if (urlRef.current !== null) {
      URL.revokeObjectURL(urlRef.current);
    }
    urlRef.current = URL.createObjectURL(chosen);
    setPreview(urlRef.current);
    setFile(chosen);
  }

  async function upload() {
    if (file === null) {
      setError("Please choose an image first.");
      return;
    }
    setError(null);
    setBusy(true);
    try {
      const result = await postScanQr(file);
      router.push(`/scan/${encodeURIComponent(result.scan_id)}`);
    } catch (e) {
      setError(
        e instanceof ApiError ? e.message : "Something went wrong. Please try again."
      );
      setBusy(false);
    }
  }

  return (
    <div className="check-form">
      <div
        className={dragOver ? "dropzone dropzone-active" : "dropzone"}
        role="button"
        tabIndex={0}
        aria-label="Choose a QR image. You can also drag and drop a file here."
        onClick={() => inputRef.current?.click()}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            inputRef.current?.click();
          }
        }}
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          pick(e.dataTransfer.files?.[0]);
        }}
      >
        <p>Drop a QR photo here, or choose a file.</p>
        <p className="char-count">PNG, JPEG or WEBP, up to 5 MB.</p>
        <input
          ref={inputRef}
          type="file"
          accept="image/png,image/jpeg,image/webp"
          aria-label="QR image file"
          onChange={(e) => {
            pick(e.target.files?.[0]);
            e.target.value = "";
          }}
        />
      </div>

      {preview !== null && file !== null && (
        <div>
          <p className="char-count">Chosen file: {file.name}</p>
          {/* eslint-disable-next-line @next/next/no-img-element -- blob: preview URL, next/image cannot optimize it */}
          <img
            src={preview}
            alt="Preview of the chosen QR image"
            className="qr-preview"
          />
        </div>
      )}

      {error !== null && (
        <p className="form-error" role="alert">
          {error}
        </p>
      )}

      <button
        type="button"
        className="btn btn-primary"
        disabled={busy || file === null}
        aria-busy={busy}
        onClick={() => void upload()}
      >
        {busy ? "Checking…" : "Check QR image"}
      </button>
    </div>
  );
}
