/* eslint-disable no-console*/

import { NextRequest, NextResponse } from 'next/server';

import { getAuthInfoFromCookie } from '@/lib/auth';
import { db } from '@/lib/db';
import { bumpSessionEpoch, getActiveUser } from '@/lib/user-guard';

export const runtime = 'nodejs';

export async function POST(request: NextRequest) {
  const storageType = process.env.NEXT_PUBLIC_STORAGE_TYPE || 'localstorage';

  // 不支持 localstorage 模式
  if (storageType === 'localstorage') {
    return NextResponse.json(
      {
        error: '不支持本地存储模式修改密码',
      },
      { status: 400 }
    );
  }

  try {
    const body = await request.json();
    const { newPassword, oldPassword } = body;
    const active = await getActiveUser(request);
    const authInfo = getAuthInfoFromCookie(request);
    if (!active.allowed || !authInfo || !authInfo.username) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }
    if (!oldPassword || typeof oldPassword !== 'string') {
      return NextResponse.json({ error: '旧密码不得为空' }, { status: 400 });
    }
    // v1.0.1：此前只要求去空格后不少于 6 位，弱口令可直接设。
    if (
      !newPassword ||
      typeof newPassword !== 'string' ||
      newPassword.trim().length < 8 ||
      !/[A-Za-z]/.test(newPassword) ||
      !/[0-9]/.test(newPassword)
    ) {
      return NextResponse.json({ error: '新密码至少 8 位，且须同时包含字母和数字' }, { status: 400 });
    }
    if (oldPassword === newPassword) {
      return NextResponse.json({ error: '新密码不能与旧密码相同' }, { status: 400 });
    }
    const username = authInfo.username;
    if (username === process.env.USERNAME) {
      return NextResponse.json(
        { error: '站长不能通过此接口修改密码' },
        { status: 403 }
      );
    }

    const valid = await db.verifyUser(username, oldPassword);
    if (!valid) {
      return NextResponse.json({ error: '旧密码错误' }, { status: 401 });
    }
    await db.changePassword(username, newPassword);
    // 改密后轮换会话纪元，旧 Cookie 立即失效；同时清掉当前 Cookie，强制重新登录
    await bumpSessionEpoch(username);
    const response = NextResponse.json({ ok: true });
    response.cookies.set('auth', '', { expires: new Date(0), path: '/' });
    return response;
  } catch (error) {
    console.error('修改密码失败:', error);
    return NextResponse.json(
      {
        error: '修改密码失败',
        details: (error as Error).message,
      },
      { status: 500 }
    );
  }
}
