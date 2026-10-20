import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import HistoryList from "./HistoryList";
import type { ScanHistoryItem } from "@/lib/api";

const ROWS: ScanHistoryItem[] = [
  {
    id: "id-1",
    type: "url",
    risk_score: 10,
    verdict: "safe",
    created_at: "2026-10-12T10:00:00",
  },
  {
    id: "id-2",
    type: "qr",
    risk_score: 80,
    verdict: "dangerous",
    created_at: "2026-10-12T11:00:00",
  },
];

describe("HistoryList", () => {
  it("renders rows with type, verdict text, score and links", () => {
    render(<HistoryList items={ROWS} />);
    expect(screen.getByText("Link")).toBeInTheDocument();
    expect(screen.getByText("QR image")).toBeInTheDocument();
    expect(screen.getByText("Looks safe so far")).toBeInTheDocument();
    expect(screen.getByText("Likely a scam")).toBeInTheDocument();
    expect(screen.getByText(/Score 10 out of 100/)).toBeInTheDocument();
    expect(screen.getByText(/Score 80 out of 100/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /Likely a scam/ })).toHaveAttribute(
      "href",
      "/scan/id-2"
    );
  });

  it("shows an empty state with a link to the checker", () => {
    render(<HistoryList items={[]} />);
    expect(screen.getByText("You have no scans yet.")).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "Check something" })
    ).toHaveAttribute("href", "/");
  });
});
