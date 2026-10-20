import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import AdminView from "./AdminView";
import { AuthContext } from "@/lib/auth";

afterEach(() => {
  vi.unstubAllGlobals();
});

function provider(user: { id: string; email: string; role: string } | null) {
  return {
    user,
    loading: false,
    refresh: () => Promise.resolve(),
    logout: () => Promise.resolve(),
  };
}

describe("AdminView access", () => {
  it("shows the restricted 403-style message for a normal user", () => {
    const spy = vi.fn();
    vi.stubGlobal("fetch", spy);
    render(
      <AuthContext.Provider value={provider({ id: "u1", email: "a@b.com", role: "user" })}>
        <AdminView />
      </AuthContext.Provider>
    );
    expect(screen.getByText("Not allowed")).toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent(/403/);
    expect(screen.getByRole("alert")).toHaveTextContent(/do not have permission/);
    expect(spy).not.toHaveBeenCalled();
  });

  it("shows the restricted message when logged out", () => {
    vi.stubGlobal("fetch", vi.fn());
    render(
      <AuthContext.Provider value={provider(null)}>
        <AdminView />
      </AuthContext.Provider>
    );
    expect(screen.getByText("Not allowed")).toBeInTheDocument();
  });
});

describe("AdminView reports", () => {
  it("renders report HTML as literal text, not markup", async () => {
    const evil = '<img src=x onerror=alert(1)> Pay now <b>urgent</b>';
    const fetchMock = vi.fn(async (url: string) => {
      if (url.startsWith("/api/admin/reports")) {
        return new Response(
          JSON.stringify([
            {
              id: "r1",
              scam_type: "phishing",
              content: evil,
              reported_value_type: "domain",
              reported_value: "evil.example",
              status: "pending",
              created_at: "2026-10-12T10:00:00Z",
            },
          ]),
          { status: 200 }
        );
      }
      return new Response("[]", { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock as unknown as typeof fetch);
    const { container } = render(
      <AuthContext.Provider
        value={provider({ id: "a1", email: "admin@example.com", role: "admin" })}
      >
        <AdminView />
      </AuthContext.Provider>
    );
    // The exact evil string must appear as text…
    expect(await screen.findByText(evil)).toBeInTheDocument();
    // …but must not become real HTML elements.
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    // Target is shown defanged as plain text, never a link.
    expect(screen.getByText("evil[.]example")).toBeInTheDocument();
    expect(container.querySelector('a[href*="evil"]')).toBeNull();
  });

  it("asks for confirmation and removes the item after approve", async () => {
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (url.startsWith("/api/admin/reports") && (!init || !init.method || (init.method as string) !== "POST")) {
        return new Response(
          JSON.stringify([
            {
              id: "r9",
              scam_type: "lottery",
              content: "You won a prize, send a fee to claim it now please.",
              reported_value_type: null,
              reported_value: null,
              status: "pending",
              created_at: "2026-10-12T10:00:00Z",
            },
          ]),
          { status: 200 }
        );
      }
      if (url === "/api/admin/reports/r9/approve") {
        return new Response(
          JSON.stringify({ report_id: "r9", status: "approved" }),
          { status: 200 }
        );
      }
      return new Response("[]", { status: 200 });
    });
    vi.stubGlobal("fetch", fetchMock as unknown as typeof fetch);
    render(
      <AuthContext.Provider
        value={provider({ id: "a1", email: "admin@example.com", role: "admin" })}
      >
        <AdminView />
      </AuthContext.Provider>
    );
    expect(
      await screen.findByText(/You won a prize/)
    ).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));
    // Confirm step appears first.
    fireEvent.click(screen.getByRole("button", { name: "Yes, approve" }));
    await waitFor(() =>
      expect(screen.queryByText(/You won a prize/)).toBeNull()
    );
  });

  it("handles 409 already-reviewed with a friendly message", async () => {
    const fetchMock = vi.fn(async (url: string) => {
      if (url === "/api/admin/reports/r7/reject") {
        return new Response(JSON.stringify({ detail: "gone" }), { status: 409 });
      }
      return new Response(
        JSON.stringify([
          {
            id: "r7",
            scam_type: "other",
            content: "Someone asked for an advance fee for a loan here.",
            reported_value_type: null,
            reported_value: null,
            status: "pending",
            created_at: "2026-10-12T10:00:00Z",
          },
        ]),
        { status: 200 }
      );
    });
    vi.stubGlobal("fetch", fetchMock as unknown as typeof fetch);
    render(
      <AuthContext.Provider
        value={provider({ id: "a1", email: "admin@example.com", role: "admin" })}
      >
        <AdminView />
      </AuthContext.Provider>
    );
    expect(await screen.findByText(/advance fee/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Reject" }));
    fireEvent.click(screen.getByRole("button", { name: "Yes, reject" }));
    expect(
      await screen.findByText(/already been reviewed/)
    ).toBeInTheDocument();
  });
});
