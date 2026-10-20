const CARD_TEXT: Record<string, { icon: string; title: string; className: string }> = {
  safe: { icon: "\u2713", title: "Looks safe so far", className: "verdict-safe" },
  suspicious: { icon: "\u26A0", title: "Be careful", className: "verdict-suspicious" },
  dangerous: { icon: "\u2715", title: "Likely a scam", className: "verdict-dangerous" },
};

function cardFor(verdict: string) {
  return (
    CARD_TEXT[verdict] ?? {
      icon: "?",
      title: "Unknown result",
      className: "verdict-unknown",
    }
  );
}

// Shared text + styling hook so history rows say the same words as the card.
export function verdictInfo(verdict: string): { title: string; className: string } {
  const card = cardFor(verdict);
  return { title: card.title, className: card.className };
}

export default function VerdictCard({
  verdict,
  riskScore,
}: {
  verdict: string;
  riskScore: number;
}) {
  const card = cardFor(verdict);
  const score = Math.max(0, Math.min(100, riskScore));
  return (
    <section
      className={`verdict-card ${card.className}`}
      aria-label={`Verdict: ${card.title}`}
    >
      <p className="verdict-title" role="status">
        <span aria-hidden="true" className="verdict-icon">
          {card.icon}
        </span>{" "}
        {card.title}
      </p>
      <p className="verdict-score-text">
        Risk score {score} out of 100
      </p>
      <div
        className="score-bar"
        role="progressbar"
        aria-label="Risk score"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={score}
        aria-valuetext={`${card.title}. Risk score ${score} out of 100.`}
      >
        <div className="score-fill" style={{ width: `${score}%` }} />
      </div>
    </section>
  );
}
