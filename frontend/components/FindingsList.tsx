import type { Finding } from "@/lib/api";

// Plain-text list of findings. React escapes text children by default,
// so explanations are always shown literally and never run as code.
export default function FindingsList({
  findings,
}: {
  findings: Finding[];
}) {
  if (findings.length === 0) {
    return <p>No strong warning signs found.</p>;
  }
  return (
    <div>
      <ul className="findings-list">
        {findings.map((f) => (
          <li key={f.rule_code}>
            <p>{f.explanation}</p>
          </li>
        ))}
      </ul>
      <details className="details-box">
        <summary>Technical details</summary>
        <ul>
          {findings.map((f) => (
            <li key={f.rule_code}>
              {f.rule_code} (weight {f.severity})
            </li>
          ))}
        </ul>
      </details>
    </div>
  );
}
