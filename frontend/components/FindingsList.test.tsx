import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import FindingsList from "./FindingsList";

describe("FindingsList", () => {
  it("shows a script payload as literal text and never runs it", () => {
    const evil = "<script>alert(1)</script>";
    const { container } = render(
      <FindingsList
        findings={[{ rule_code: "X", severity: 10, explanation: evil }]}
      />
    );
    // The exact text is visible to the reader…
    expect(screen.getByText(evil)).toBeInTheDocument();
    // …but no script element exists in the page, so nothing runs.
    expect(container.querySelector("script")).toBeNull();
  });

  it("hides rule codes except inside the details section", () => {
    render(
      <FindingsList
        findings={[
          { rule_code: "SECRET_CODE", severity: 35, explanation: "Plain words." },
        ]}
      />
    );
    expect(screen.getByText("Plain words.")).toBeInTheDocument();
    const details = screen.getByText("Technical details").closest("details");
    expect(details?.textContent).toContain("SECRET_CODE");
  });

  it("shows a friendly line when there are no findings", () => {
    render(<FindingsList findings={[]} />);
    expect(
      screen.getByText("No strong warning signs found.")
    ).toBeInTheDocument();
  });
});
