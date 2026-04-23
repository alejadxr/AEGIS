import type { Metadata } from 'next';
import './globals.css';
import { Noto_Sans } from "next/font/google";
import { cn } from "@/lib/utils";

const notoSans = Noto_Sans({subsets:['latin'],variable:'--font-sans'});

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
    <html lang="en" data-theme="light" suppressHydrationWarning className={cn("font-sans light", notoSans.variable)}>
      <head>
        <script
          dangerouslySetInnerHTML={{
            __html: `(function(){try{var t=localStorage.getItem('aegis-theme')||'light';var d=document.documentElement;d.setAttribute('data-theme',t);if(t==='dark'){d.classList.add('dark');d.classList.remove('light')}else{d.classList.add('light');d.classList.remove('dark')}var o=new MutationObserver(function(ms){ms.forEach(function(m){if(m.attributeName==='data-theme'){var v=d.getAttribute('data-theme');if(v==='dark'){d.classList.add('dark');d.classList.remove('light')}else{d.classList.add('light');d.classList.remove('dark')}}})});o.observe(d,{attributes:true,attributeFilter:['data-theme']})}catch(e){}})();`,
          }}
        />
      </head>
      <body className="min-h-screen antialiased">
        {children}
      </body>
    </html>
  );
}
