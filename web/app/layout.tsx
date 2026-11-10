import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "mr-amt",
  description: "Static Android sample review",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <main>{children}</main>
      </body>
    </html>
  );
}
