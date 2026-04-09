'use client';

import { useRouter } from 'next/navigation';
import { GuideTour } from '@/components/shared/GuideTour';

export default function GuidePage() {
  const router = useRouter();
  return (
    <GuideTour onClose={() => router.push('/dashboard')} />
  );
}
