import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import ApiKeysView from "./ApiKeysView";
import { AuthContext } from "@/lib/auth";

const replace = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace }),
}));

afterEach(() => {
  vi.unstubAllGlobals();
  replace.mockClear();
});

function renderLoggedIn(fetchMock: ReturnType<typeof vi.fn>) {
  vi.stubGlobal("fetch", fetchMock as unknown as typeof fetch);
  return render(
    <AuthContext.Provider
      value={{
        user: { id: "u1", email: "dev@example.com", role: "user" },
        loading: false,
        refresh: () => Promise.resolve(),
        logout: () => Promise.resolve(),
      }}
    >
      <ApiKeysView />
    </AuthContext.Provider>
  );
}

describe("ApiKeysView", () => {
  it("shows the full key once, then removes it from the DOM after closing", async () => {
    const secret = "sk-test-SECRET-ONLY-ONCE-123";
    const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
      if (typeof url === "string" && url.endsWith("/usage")) {
        return new Response(
          JSON.stringify({ days: [], today_remaining: 100, daily_limit: 100 }),
          { status: 200 }
        );
      }
      if (url === "/api/keys" && (!init || !init.method || init.method === undefined)) {
        return new Response(JSON.stringify([]), { status: 200 });
      }
      if (url === "/api/keys" && init?.method === "POST") {
        return new Response(
          JSON.stringify({
            id: "k1",
            name: "My website",
            prefix: "sk-test-SEC",
            full_key: secret,
          }),
          { status: 200 }
        );
      }
      return new Response(JSON.stringify([]), { status: 200 });
    });
    renderLoggedIn(fetchMock);

    // Wait for the empty state, then create a key.
    expect(await screen.findByText(/You have no API keys yet/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Key name"), {
      target: { value: "My website" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Create key" }));

    // Full key appears with the one-time warning.
    expect(await screen.findByText(secret)).toBeInTheDocument();
    expect(
      screen.getByText(/This is the only time you will see this key/)
    ).toBeInTheDocument();

    // Closing the box forgets the secret: it must leave the DOM entirely.
    fireEvent.click(screen.getByRole("button", { name: "Close" }));
    await waitFor(() => expect(screen.queryByText(secret)).toBeNull());
    expect(
      screen.queryByText(/This is the only time you will see this key/)
    ).toBeNull();
  });

  it("validates the key name length without calling the API", async () => {
    const fetchMock = vi.fn(async () => {
      return new Response(JSON.stringify([]), { status: 200 });
    });
    renderLoggedIn(fetchMock);
    expect(await screen.findByText(/You have no API keys yet/)).toBeInTheDocument();
    const callsBefore = fetchMock.mock.calls.length;
    fireEvent.click(screen.getByRole("button", { name: "Create key" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/1 to 50/);
    expect(fetchMock.mock.calls.length).toBe(callsBefore);
  });

  it("shows a placeholder curl example, never a real key", async () => {
    const fetchMock = vi.fn(async () => {
      return new Response(JSON.stringify([]), { status: 200 });
    });
    renderLoggedIn(fetchMock);
    const box = await screen.findByLabelText("Example curl command");
    expect(box.textContent).toContain("YOUR_API_KEY");
    expect(box.textContent).not.toContain("sk-live");
  });
});
