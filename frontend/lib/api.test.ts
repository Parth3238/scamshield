import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, getScan, postScan } from "./api";

function mockFetch(status: number, headers: Record<string, string> = {}) {
  const res = new Response(null, { status, headers });
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue(res) as unknown as typeof fetch
  );
  return vi.mocked(fetch);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("api wrapper", () => {
  it("sends cookies with requests", async () => {
    const scan = {
      scan_id: "1",
      type: "url",
      risk_score: 0,
      verdict: "safe",
      summary: "ok",
      findings: [],
      redirect_chain: [],
      notes: [],
    };
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify(scan), { status: 200 })
      ) as unknown as typeof fetch
    );
    const fetchMock = vi.mocked(fetch);
    await postScan({ type: "url", input: "https://example.com" });
    expect(fetchMock).toHaveBeenCalledOnce();
    const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(init.credentials).toBe("include");
  });

  it("turns 429 into a wait message using Retry-After", async () => {
    mockFetch(429, { "Retry-After": "30" });
    try {
      await getScan("abc");
      expect.unreachable("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(ApiError);
      expect((e as ApiError).message).toContain("30 seconds");
    }
  });

  it("never shows raw server text on 500", async () => {
    const res = new Response("Traceback: secret stack trace", { status: 500 });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(res) as unknown as typeof fetch
    );
    try {
      await getScan("abc");
      expect.unreachable("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(ApiError);
      expect((e as ApiError).message).not.toContain("Traceback");
      expect((e as ApiError).message).toContain("try again later");
    }
  });

  it("reports unreachable servers kindly", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("boom")) as unknown as typeof fetch
    );
    try {
      await postScan({ type: "upi", input: "a@b" });
      expect.unreachable("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(ApiError);
      expect((e as ApiError).message).toContain("Could not reach the server");
    }
  });
});
