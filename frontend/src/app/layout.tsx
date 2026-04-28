import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import Link from "next/link";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "REAPER Scanner",
  description: "AI Agent Vulnerability Scanner",
};

function Nav() {
  return (
    <nav className="border-b border-[var(--card-border)] bg-[var(--card)]">
      <div className="mx-auto max-w-7xl px-6 py-4 flex items-center gap-8">
        <Link href="/" className="flex items-center gap-2 font-bold text-lg tracking-tight">
          <span className="text-[var(--accent)]">REAPER</span>
          <span className="text-[var(--muted)] text-sm font-normal">v0.1.0</span>
        </Link>
        <div className="flex gap-6 text-sm">
          <Link href="/scan" className="hover:text-[var(--accent)] transition-colors">
            New Scan
          </Link>
          <Link href="/catalog" className="hover:text-[var(--accent)] transition-colors">
            Threat Catalog
          </Link>
          <Link href="/history" className="hover:text-[var(--accent)] transition-colors">
            History
          </Link>
        </div>
      </div>
    </nav>
  );
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${geistMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col">
        <Nav />
        <main className="flex-1 mx-auto max-w-7xl w-full px-6 py-8">
          {children}
        </main>
      </body>
    </html>
  );
}
