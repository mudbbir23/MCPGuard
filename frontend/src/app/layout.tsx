import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import { Navigation } from "@/components/Navigation";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "MCPGuard | Security Scanner for Model Context Protocol",
  description: "Detect tool poisoning, vulnerable dependencies, and excessive permissions in MCP servers.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body
        className={`${inter.className} bg-[#0a0a0a] text-white min-h-screen flex flex-col antialiased`}
      >
        <Navigation />
        {children}
      </body>
    </html>
  );
}
