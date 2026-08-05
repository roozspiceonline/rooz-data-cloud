import type { Metadata } from "next";
import type { ReactNode } from "react";
import { QueryProvider } from "@/providers/query-provider";
import "./globals.css";

export const metadata: Metadata = {
  title: { default: "Rooz Data Cloud", template: "%s · Rooz Data Cloud" },
  description: "Build, run, and manage secure cloud Agents.",
};

export default function RootLayout({ children }: Readonly<{ children: ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <a className="skip-link" href="#main-content">Skip to main content</a>
        <QueryProvider>{children}</QueryProvider>
      </body>
    </html>
  );
}
