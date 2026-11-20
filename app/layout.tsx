import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = {
  title: "P7 / FORENSIC — Analyse forensique post-phishing",
  description: "P7 — Analyse d'emails .eml : headers, IOCs, pièces jointes et score de risque. Laboratoire local, anonymisé.",
};
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return <html lang="fr"><body>{children}</body></html>;
}
