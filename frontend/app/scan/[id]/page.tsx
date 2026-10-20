import { Suspense } from "react";
import ScanResultInner from "./ScanResultInner";

// The result id only exists at request time, so the client component that
// reads it streams in behind Suspense instead of blocking the prerender.
export default function ScanResultPage() {
  return (
    <Suspense
      fallback={
        <div>
          <h1>Checking your scan…</h1>
          <p role="status">Loading the result, please wait.</p>
        </div>
      }
    >
      <ScanResultInner />
    </Suspense>
  );
}
