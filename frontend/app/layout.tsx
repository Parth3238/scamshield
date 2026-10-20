import type { Metadata } from "next";
import Header from "@/components/Header";
import { AuthProvider } from "@/lib/auth";
import "./globals.css";

export const metadata: Metadata = {
  title: "ScamShield — Check scams simply",
  description:
    "Paste a link, message or UPI ID and see the warning signs in simple words.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>
          <Header />
          <main className="container">{children}</main>
          <footer className="site-footer">
            <p>
              ScamShield checks warning signs only. It cannot prove something is
              safe. Never share OTPs or PINs with anyone.
            </p>
          </footer>
        </AuthProvider>
      </body>
    </html>
  );
}
