import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Next.js OAuth 2.1 Consumer | SWYRA M Auth",
  description: "End-to-End Next.js test consumer application for SWYRA M Auth identity provider.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-[#07090c] text-[#f1f3f5] antialiased selection:bg-[#0066B1] selection:text-white">
        <header className="h-16 border-b border-[#21262d] bg-[#0b0e14]/80 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-40">
          <div className="flex items-center gap-3">
            <div className="flex h-4 gap-1 items-center">
              <div className="w-[3px] h-3.5 bg-[#0066B1] -skew-x-12" />
              <div className="w-[3px] h-3.5 bg-[#1C69D4] -skew-x-12" />
              <div className="w-[3px] h-3.5 bg-[#E22718] -skew-x-12" />
            </div>
            <span className="font-mono text-xs uppercase tracking-wider text-neutral-400">
              <span className="text-white font-medium">SWYRA //</span> Next.js Test App
            </span>
          </div>

          <div className="flex items-center gap-3 text-xs font-mono text-neutral-400">
            <span className="inline-block size-2 rounded-full bg-emerald-500 animate-pulse"></span>
            OAuth 2.1 Ready
          </div>
        </header>

        <main className="max-w-6xl mx-auto p-6 md:p-10">
          {children}
        </main>
      </body>
    </html>
  );
}
