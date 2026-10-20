import ReportForm from "@/components/ReportForm";

export default function ReportPage() {
  return (
    <div>
      <h1>Report a scam</h1>
      <p className="lede">
        Warn others. Your report is checked by our team before it appears
        publicly.
      </p>
      <ReportForm />
    </div>
  );
}
