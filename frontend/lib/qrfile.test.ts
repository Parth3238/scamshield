import { describe, expect, it } from "vitest";
import { QR_MAX_BYTES, validateQrFile } from "./qrfile";

function makeFile(
  bytes: number,
  name = "qr.png",
  type = "image/png"
): File {
  const data = new Uint8Array(Math.max(bytes, 1));
  const file = new File([data.slice(0, bytes)], name, { type });
  // jsdom may report size 0 for empty parts; define it explicitly.
  Object.defineProperty(file, "size", { value: bytes });
  return file;
}

describe("validateQrFile", () => {
  it("accepts PNG, JPEG and WEBP images", () => {
    expect(validateQrFile(makeFile(1000, "a.png", "image/png"))).toBeNull();
    expect(validateQrFile(makeFile(1000, "a.jpg", "image/jpeg"))).toBeNull();
    expect(validateQrFile(makeFile(1000, "a.webp", "image/webp"))).toBeNull();
  });

  it("rejects wrong file types", () => {
    expect(validateQrFile(makeFile(1000, "a.txt", "text/plain"))).toContain(
      "PNG, JPEG or WEBP"
    );
    expect(validateQrFile(makeFile(1000, "a.pdf", "application/pdf"))).not.toBeNull();
  });

  it("rejects files bigger than 5 MB", () => {
    expect(
      validateQrFile(makeFile(QR_MAX_BYTES + 1, "big.png", "image/png"))
    ).toContain("max 5 MB");
  });

  it("accepts a file of exactly 5 MB", () => {
    expect(
      validateQrFile(makeFile(QR_MAX_BYTES, "edge.png", "image/png"))
    ).toBeNull();
  });

  it("rejects empty files", () => {
    expect(validateQrFile(makeFile(0, "empty.png", "image/png"))).toContain(
      "empty"
    );
  });
});
