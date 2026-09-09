/*
 * Network Attack Path Analyzer
 * Author: MD Jubayer Khan Akash
 * Project version: 0.7.0
 */

import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Network Attack Path Analyzer",
  description: "Defensive network attack-path analysis, risk scoring, simulation, reporting, and AI-assisted explanation."
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
