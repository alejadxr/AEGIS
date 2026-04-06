import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'AEGIS | Autonomous Defense Platform',
  description: 'AI-powered cybersecurity defense platform with autonomous threat detection, incident response, and deception capabilities.',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" data-theme="dark" suppressHydrationWarning>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `(function(){try{var s=localStorage.getItem('aegis-theme');var m=window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches;var t=s|| (m?'light':'dark');document.documentElement.setAttribute('data-theme',t);}catch(e){}})();`,
          }}
        />
      </head>
      <body className="min-h-screen antialiased">
        {children}
      </body>
    </html>
  );
}
