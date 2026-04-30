import { NextRequest, NextResponse } from 'next/server';

const FIREWALL_AGENT_URL = 'http://100.93.30.20:8765';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params;
  const target = path.join('/');
  const url = request.nextUrl.searchParams.toString();
  const fullUrl = url
    ? `${FIREWALL_AGENT_URL}/${target}?${url}`
    : `${FIREWALL_AGENT_URL}/${target}`;

  try {
    const res = await fetch(fullUrl, {
      headers: { Accept: 'application/json' },
      cache: 'no-store',
      signal: AbortSignal.timeout(8000),
    });

    if (!res.ok) {
      return NextResponse.json(
        { error: `Firewall agent returned ${res.status}` },
        { status: res.status }
      );
    }

    const data = await res.json();
    return NextResponse.json(data);
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Unknown error';
    return NextResponse.json(
      { error: 'Firewall agent unreachable', detail: message },
      { status: 502 }
    );
  }
}
