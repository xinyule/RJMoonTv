/* eslint-disable @typescript-eslint/no-explicit-any */

import { NextRequest, NextResponse } from 'next/server';

import { getConfig } from '@/lib/config';
import { fetchValidated, proxyAllowPrivate } from '@/lib/proxy-guard';
import { getActiveUser } from '@/lib/user-guard';

export const runtime = 'nodejs';

export async function GET(request: NextRequest) {
  const active = await getActiveUser(request);
  if (!active.allowed) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  const { searchParams } = new URL(request.url);
  const url = searchParams.get('url');
  const source = searchParams.get('moontv-source');

  if (!url) {
    return NextResponse.json({ error: 'Missing url' }, { status: 400 });
  }
  const config = await getConfig();
  const liveSource = config.LiveConfig?.find((s: any) => s.key === source);
  if (!liveSource) {
    return NextResponse.json({ error: 'Source not found' }, { status: 404 });
  }
  const ua = liveSource.ua || 'AptvPlayer/1.4.10';

  try {
    const decodedUrl = url;
    const response = await fetchValidated(decodedUrl, {
      cache: 'no-cache',
      headers: {
        'User-Agent': ua,
      },
    }, proxyAllowPrivate(), 15000);

    if (!response.ok) {
      return NextResponse.json({ error: 'Failed to fetch', message: response.statusText }, { status: 500 });
    }

    const contentType = response.headers.get('Content-Type');
    if (response.body) {
      response.body.cancel();
    }
    if (contentType?.includes('video/mp4')) {
      return NextResponse.json({ success: true, type: 'mp4' }, { status: 200 });
    }
    if (contentType?.includes('video/x-flv')) {
      return NextResponse.json({ success: true, type: 'flv' }, { status: 200 });
    }
    return NextResponse.json({ success: true, type: 'm3u8' }, { status: 200 });
  } catch (error) {
    return NextResponse.json({ error: 'Failed to fetch', message: error }, { status: 500 });
  }
}