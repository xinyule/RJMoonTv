/* eslint-disable no-console */

import { NextRequest, NextResponse } from 'next/server';

import { getActiveUser } from '@/lib/user-guard';
import { getAvailableApiSites } from '@/lib/config';

export const runtime = 'nodejs';

// OrionTV 兼容接口
export async function GET(request: NextRequest) {
  const active = await getActiveUser(request);
  if (!active.allowed || !active.username) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
  }
  const authInfo = { username: active.username };
  try {
    const apiSites = await getAvailableApiSites(authInfo.username);

    return NextResponse.json(apiSites);
  } catch (error) {
    return NextResponse.json({ error: '获取资源失败' }, { status: 500 });
  }
}
