import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import RequireAuth from "./RequireAuth";
import { AuthContext } from "@/lib/auth";

const replace = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ replace }),
}));

afterEach(() => {
  replace.mockClear();
});

function renderWithUser(user: { id: string; email: string; role: string } | null) {
  return render(
    <AuthContext.Provider
      value={{
        user,
        loading: false,
        refresh: () => Promise.resolve(),
        logout: () => Promise.resolve(),
      }}
    >
      <RequireAuth>
        <p>Secret page</p>
      </RequireAuth>
    </AuthContext.Provider>
  );
}

describe("RequireAuth", () => {
  it("redirects to login when there is no user", () => {
    renderWithUser(null);
    expect(replace).toHaveBeenCalledWith("/login");
    expect(screen.queryByText("Secret page")).toBeNull();
  });

  it("shows the page when logged in", () => {
    renderWithUser({ id: "1", email: "a@b.com", role: "user" });
    expect(screen.getByText("Secret page")).toBeInTheDocument();
    expect(replace).not.toHaveBeenCalled();
  });
});
