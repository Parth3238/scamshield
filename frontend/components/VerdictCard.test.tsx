import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import VerdictCard from "./VerdictCard";

describe("VerdictCard", () => {
  it("renders safe text for a safe verdict", () => {
    render(<VerdictCard verdict="safe" riskScore={10} />);
    expect(screen.getByText("Looks safe so far")).toBeInTheDocument();
    expect(screen.getByText("Risk score 10 out of 100")).toBeInTheDocument();
  });

  it("renders careful text for a suspicious verdict", () => {
    render(<VerdictCard verdict="suspicious" riskScore={45} />);
    expect(screen.getByText("Be careful")).toBeInTheDocument();
    const bar = screen.getByRole("progressbar", { name: "Risk score" });
    expect(bar).toHaveAttribute("aria-valuenow", "45");
  });

  it("renders scam text for a dangerous verdict", () => {
    render(<VerdictCard verdict="dangerous" riskScore={85} />);
    expect(screen.getByText("Likely a scam")).toBeInTheDocument();
    expect(screen.getByText("Risk score 85 out of 100")).toBeInTheDocument();
  });

  it("does not rely on color alone: icon and text are always present", () => {
    const { container } = render(
      <VerdictCard verdict="dangerous" riskScore={85} />
    );
    // Icon glyph plus heading text plus an accessible progressbar label.
    expect(container.querySelector(".verdict-icon")).toHaveTextContent("✕");
    expect(
      screen.getByRole("progressbar", { name: "Risk score" })
    ).toHaveAccessibleName();
  });
});
