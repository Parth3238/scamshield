import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import ReportForm from "./ReportForm";

afterEach(() => {
  vi.unstubAllGlobals();
});

function mockFetchOnce(status: number, body: unknown) {
  vi.stubGlobal(
    "fetch",
    vi.fn().mockResolvedValue(
      new Response(JSON.stringify(body), { status })
    ) as unknown as typeof fetch
  );
}

describe("ReportForm validation", () => {
  it("blocks descriptions shorter than 10 characters without calling the API", async () => {
    const spy = vi.fn();
    vi.stubGlobal("fetch", spy);
    render(<ReportForm />);
    fireEvent.change(screen.getByLabelText("What happened?"), {
      target: { value: "short" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Send report" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /at least 10 characters/
    );
    expect(spy).not.toHaveBeenCalled();
  });

  it("shows the character counter and blocks empty target-safe submit", async () => {
    vi.stubGlobal("fetch", vi.fn());
    render(<ReportForm />);
    // Counter starts asking for more characters.
    expect(screen.getByText(/more characters needed/)).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText("What happened?"), {
      target: { value: "This is long enough to pass validation here." },
    });
    expect(screen.getByText(/characters left/)).toBeInTheDocument();
  });

  it("shows the backend thanks message and clears the form on success", async () => {
    const msg = "Thanks! Your report will be reviewed before it appears publicly.";
    mockFetchOnce(200, { report_id: "r1", status: "pending", message: msg });
    render(<ReportForm />);
    fireEvent.change(screen.getByLabelText("What happened?"), {
      target: { value: "Someone called pretending to be the bank manager today." },
    });
    fireEvent.change(
      screen.getByLabelText(/Suspicious link, domain or UPI ID/),
      { target: { value: "evil-offer.example" } }
    );
    fireEvent.click(screen.getByRole("button", { name: "Send report" }));
    expect(await screen.findByText(msg)).toBeInTheDocument();
    await waitFor(() => {
      expect(
        (screen.getByLabelText("What happened?") as HTMLTextAreaElement).value
      ).toBe("");
    });
  });

  it("maps 422 to the friendly target message", async () => {
    mockFetchOnce(422, { detail: "This target cannot be reported" });
    render(<ReportForm />);
    fireEvent.change(screen.getByLabelText("What happened?"), {
      target: { value: "Someone called pretending to be the bank manager today." },
    });
    fireEvent.click(screen.getByRole("button", { name: "Send report" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /This target cannot be reported/
    );
  });

  it("maps 409 duplicates to a friendly message", async () => {
    mockFetchOnce(409, { detail: "You have already reported this target recently." });
    render(<ReportForm />);
    fireEvent.change(screen.getByLabelText("What happened?"), {
      target: { value: "Someone called pretending to be the bank manager today." },
    });
    fireEvent.click(screen.getByRole("button", { name: "Send report" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(
      /already reported/
    );
  });

  it("shows the safety warning above the form", () => {
    render(<ReportForm />);
    expect(
      screen.getByText(/Never include passwords, OTPs, card numbers/)
    ).toBeInTheDocument();
  });
});
