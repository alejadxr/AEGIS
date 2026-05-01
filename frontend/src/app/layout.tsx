import type { Metadata } from 'next';
import './globals.css';
import { Noto_Sans } from "next/font/google";
import { cn } from "@/lib/utils";

const notoSans = Noto_Sans({subsets:['latin'],variable:'--font-sans'});

export const metadata: Metadata = {
  title: 'AEGIS | Open-Source Ransomware Defense and EDR Platform',
  description: 'Self-hosted autonomous defense platform. Detects ransomware, lateral movement, and intrusions in <1 ms with 134 Sigma rules. Offline-capable. No cloud AI required. Free, AGPL-3.0.',
  keywords: [
    'open source EDR',
    'self-hosted ransomware defense',
    'deterministic SOAR',
    'open source SIEM alternative',
    'open source XDR',
    'MITRE ATT&CK detection',
    'ransomware kill-chain detection',
    'offline security platform',
    'Sigma rules',
    'autonomous incident response',
  ],
  authors: [{ name: 'AEGIS Contributors' }],
  openGraph: {
    type: 'website',
    siteName: 'AEGIS',
    title: 'AEGIS — Open-Source Ransomware Defense and EDR Platform',
    description: 'Self-hosted. Deterministic-first. Detects ransomware in <1 ms with 134 Sigma rules. Offline-capable. Free, AGPL-3.0.',
    url: 'https://github.com/alejadxr/AEGIS',
    images: [
      {
        url: '/og-image.png',
        width: 1200,
        height: 630,
        alt: 'AEGIS — Autonomous Defense Platform',
      },
    ],
  },
  twitter: {
    card: 'summary_large_image',
    title: 'AEGIS — Open-Source Ransomware Defense and EDR Platform',
    description: 'Self-hosted. Deterministic-first. Detects ransomware in <1 ms. 134 Sigma rules. Offline-capable. Free, AGPL-3.0.',
    images: ['/og-image.png'],
  },
  robots: {
    index: true,
    follow: true,
  },
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
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{
            __html: JSON.stringify({
              "@context": "https://schema.org",
              "@graph": [
                {
                  "@type": "SoftwareApplication",
                  "name": "AEGIS",
                  "alternateName": "AEGIS Autonomous Defense Platform",
                  "description": "Open-source, self-hosted autonomous cybersecurity defense platform. Detects ransomware, lateral movement, and intrusions in <1 ms using 134 Sigma rules. Offline-capable. No cloud AI required.",
                  "applicationCategory": "SecurityApplication",
                  "operatingSystem": "Linux, macOS, Windows",
                  "softwareVersion": "1.6.0",
                  "datePublished": "2026-05-01",
                  "license": "https://www.gnu.org/licenses/agpl-3.0.html",
                  "url": "https://github.com/alejadxr/AEGIS",
                  "downloadUrl": "https://github.com/alejadxr/AEGIS/releases/tag/v1.6.0",
                  "codeRepository": "https://github.com/alejadxr/AEGIS",
                  "programmingLanguage": ["Python", "TypeScript", "Rust"],
                  "keywords": "open source EDR, self-hosted ransomware defense, deterministic SOAR, open source SIEM alternative, MITRE ATT&CK detection, ransomware kill-chain, offline security platform",
                  "featureList": [
                    "134 Sigma correlation rules with <1 ms evaluation",
                    "12 ransomware-specific Sigma rules (MITRE T1490/T1486/T1105/T1218/T1021)",
                    "Ransomware kill-chain detection and automated response",
                    "RaaS threat intelligence feed (RansomLook + CISA, every 6 hours)",
                    "Snapshot recovery orchestration (tmutil/btrfs/zfs/VSS)",
                    "SSH and HTTP honeypots with breadcrumb credential traps",
                    "Offline-capable (AEGIS_AI_MODE=offline)",
                    "Real firewall enforcement via pfctl/iptables",
                    "Hardened Rust endpoint agent with entropy classifier",
                    "Self-hosted with Docker Compose"
                  ],
                  "offers": {
                    "@type": "Offer",
                    "price": "0",
                    "priceCurrency": "USD"
                  }
                },
                {
                  "@type": "FAQPage",
                  "mainEntity": [
                    {
                      "@type": "Question",
                      "name": "What is AEGIS cybersecurity?",
                      "acceptedAnswer": {
                        "@type": "Answer",
                        "text": "AEGIS is an open-source, self-hosted autonomous defense platform that detects ransomware, lateral movement, and intrusions in real time. It evaluates 134 Sigma rules in <1 ms, runs deception honeypots, enforces firewall blocks, and orchestrates snapshot recovery — without requiring a cloud AI service."
                      }
                    },
                    {
                      "@type": "Question",
                      "name": "How does AEGIS detect ransomware?",
                      "acceptedAnswer": {
                        "@type": "Answer",
                        "text": "AEGIS v1.6 ships 12 ransomware-specific Sigma rules and 1 kill-chain detection mapped to MITRE T1490, T1486, T1105, T1218, and T1021. It detects shadow-copy deletion, mass file encryption (entropy ≥7.5 bits/byte at ≥50 writes/s), canary file trips, ransom note drops, LOLBin staging, SMB/RDP/WinRM lateral movement — all in <1 ms per event."
                      }
                    },
                    {
                      "@type": "Question",
                      "name": "Does AEGIS work without an AI API key?",
                      "acceptedAnswer": {
                        "@type": "Answer",
                        "text": "Yes. Set AEGIS_AI_MODE=offline and the entire detection and response stack runs on deterministic Sigma rules, static playbooks, and Jinja2 templates. No external API calls are made."
                      }
                    }
                  ]
                }
              ]
            })
          }}
        />
      </head>
      <body className="min-h-screen antialiased">
        {children}
      </body>
    </html>
  );
}
