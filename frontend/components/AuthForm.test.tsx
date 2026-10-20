import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import AuthForm from "./AuthForm";

function mockFetchOnce(status: number, body: unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue(
      new Response(JSON.stringify(body), { status })
    ) as unknown as typeof fetch
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

async function fillAndSubmit(email: string, password: string) {
  fireEvent.change(screen.getByLabelText("Email"), {
    target: { value: email },
  });
  fireEvent.change(screen.getByLabelText("Password"), {
    target: { value: password },
  });
  fireEvent.click(screen.getByRole("button", { name: "Log in" }));
}

describe("AuthForm login", () => {
  it("shows the length hint and blocks short passwords", async () => {
    const spy = vi.fn();
    vi.stubGlobal("fetch", spy);
    render(<AuthForm mode="login" />);
    expect(screen.getByText(/now 0/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "short" },
    });
    expect(screen.getByText(/now 5/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("Email"), {
      target: { value: "a@b.com" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Log in" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/10 to 128 characters \(now 5\)/);
    expect(spy).not.toHaveBeenCalled();
  });

  it("shows only the generic error on 401", async () => {
    mockFetchOnce(401, { detail: "Invalid email or password" });
    render(<AuthForm mode="login" onAuth={vi.fn()} />);
    await fillAndSubmit("a@b.com", "wrongpassword1");
    expect(
      await screen.findByText("Invalid email or password")
    ).toBeInTheDocument();
  });

  it("toggles password visibility", () => {
    render(<AuthForm mode="login" />);
    const input = screen.getByLabelText("Password") as HTMLInputElement;
    expect(input.type).toBe("password");
    fireEvent.click(screen.getByRole("button", { name: "Show password" }));
    expect(input.type).toBe("text");
  });
});

describe("AuthForm register", () => {
  it("shows the backend message exactly and links to login", async () => {
    const msg = "If this email can be registered, your account is created";
    mockFetchOnce(200, { message: msg });
    render(<AuthForm mode="register" />);
    fireEvent.change(screen.getByLabelText("Email"), {
      target: { value: "new@example.com" },
    });
    fireEvent.change(screen.getByLabelText("Password"), {
      target: { value: "longpassword1" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Register" }));
    expect(await screen.findByText(msg)).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Go to login" })
    ).toHaveAttribute("href", "/login");
    await waitFor(() =>
      expect(screen.queryByRole("button", { name: "Register" })).toBeNull()
    );
  });
});
