import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import TrendingView from "./TrendingView";

afterEach(() => {
  vi.unstubAllGlobals();
});

function stubFetch(handler: (url: string) => unknown) {
  const mock = vi.fn(async (url: string) => {
    return new Response(JSON.stringify(handler(url)), { status: 200 });
  });
  vi.stubGlobal("fetch", mock as unknown as typeof fetch);
  return mock;
}

function delay(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

describe("TrendingView", () => {
  it("does not call search for fewer than 3 characters", async () => {
    const mock = stubFetch(() => []);
    render(<TrendingView />);
    // Initial trending load finishes.
    await screen.findByText("Most reported this week");
    const before = mock.mock.calls.length;

    fireEvent.change(screen.getByLabelText("Search by name or link"), {
      target: { value: "ab" },
    });
    // Wait longer than the 400 ms debounce: still no search call.
    await delay(700);
    const searchCalls = mock.mock.calls.filter(([url]) =>
      String(url).includes("/api/campaigns/search")
    );
    expect(searchCalls).toHaveLength(0);
    expect(mock.mock.calls.length).toBe(before);
    expect(
      screen.getByText("Type at least 3 characters to search.")
    ).toBeInTheDocument();
  });

  it("searches after 3+ characters with debounce", async () => {
    const results = [
      {
        title: "Fake KYC gang",
        scam_type: "fake_kyc",
        report_count: 5,
        last_seen: "2026-10-12T10:00:00Z",
        sample_targets: ["evil.example"],
      },
    ];
    const mock = stubFetch((url: string) =>
      url.includes("/api/campaigns/search") ? results : []
    );
    render(<TrendingView />);
    await screen.findByText("Most reported this week");

    fireEvent.change(screen.getByLabelText("Search by name or link"), {
      target: { value: "kyc" },
    });
    expect(await screen.findByText("Fake KYC gang")).toBeInTheDocument();
    const searchCalls = mock.mock.calls.filter(([url]) =>
      String(url).includes("/api/campaigns/search")
    );
    expect(searchCalls.length).toBeGreaterThanOrEqual(1);
    await waitFor(() =>
      expect(screen.getByText("1 result found.")).toBeInTheDocument()
    );
  });

  it("shows loading, empty and disclaimer states", async () => {
    stubFetch(() => []);
    render(<TrendingView />);
    expect(screen.getByText(/Loading trending scams/)).toBeInTheDocument();
    expect(
      await screen.findByText(
        "Reports come from users and are reviewed, but may not be perfect."
      )
    ).toBeInTheDocument();
    expect(
      await screen.findByText("No scams to show right now. Please check again later.")
    ).toBeInTheDocument();
  });
});
