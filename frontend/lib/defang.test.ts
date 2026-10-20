import { describe, expect, it } from "vitest";
import { defangUrl } from "./defang";

describe("defangUrl", () => {
  it("defangs an https URL", () => {
    expect(defangUrl("https://example.com/login")).toBe(
      "hxxps://example[.]com/login"
    );
  });

  it("defangs an http URL with subdomains", () => {
    expect(defangUrl("http://a.b.example.co.in/x")).toBe(
      "hxxp://a[.]b[.]example[.]co[.]in/x"
    );
  });

  it("leaves dots in the path alone", () => {
    expect(defangUrl("https://example.com/file.name.html")).toBe(
      "hxxps://example[.]com/file.name.html"
    );
  });

  it("handles uppercase schemes and hosts", () => {
    expect(defangUrl("HTTPS://EXAMPLE.COM")).toBe("hxxps://EXAMPLE[.]COM");
  });

  it("defangs a bare domain", () => {
    expect(defangUrl("example.com")).toBe("example[.]com");
  });

  it("leaves plain text alone", () => {
    expect(defangUrl("hello world")).toBe("hello world");
  });
});
