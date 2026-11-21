import type { Metadata } from "next";
import { IBM_Plex_Mono, Manrope } from "next/font/google";
const monoFont = IBM_Plex_Mono({ subsets: ["latin"], weight: ["400", "600"], variable: "--font-mono", display: "swap" });
const displayFont = Manrope({ subsets: ["latin"], weight: ["400", "600", "800"], variable: "--font-display", display: "swap" });
import "./globals.css";
export const metadata: Metadata = {
  title: "P7 / FORENSIC — Analyse forensique post-phishing",
  description: "P7 — Analyse d'emails .eml : headers, IOCs, pièces jointes et score de risque. Laboratoire local, anonymisé.",
};
export default function RootLayout({ children }: { children: React.ReactNode }) {
  return <html lang="fr" className={`${monoFont.variable} ${displayFont.variable}`}><body>{children}</body></html>;
}
