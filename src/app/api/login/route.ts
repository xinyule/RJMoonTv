/* eslint-disable no-console,@typescript-eslint/no-explicit-any */
import { NextRequest, NextResponse } from 'next/server';

import { getConfig } from '@/lib/config';
import { db } from '@/lib/db';
import { ensureSessionEpoch } from '@/lib/user-guard';

export const runtime = 'nodejs';

// 读取存储类型环境变量，默认 localstorage
const STORAGE_TYPE =
  (process.env.NEXT_PUBLIC_STORAGE_TYPE as
    | 'localstorage'
    | 'redis'
    | 'upstash'
    | 'kvrocks'
    | undefined) || 'localstorage';

// v1.0.1：登录限流（内存级，单实例）。scrypt 验密本身很耗 CPU，
// 不限流既能爆破弱口令、也能当 CPU 消耗点。
const LOGIN_ATTEMPTS = new Map<string, { count: number; firstAt: number }>();
function loginClientIp(req: NextRequest): string {
  return (
    req.headers.get('x-forwarded-for')?.split(',')[0].trim() || 'unknown'
  );
}
function isLoginRateLimited(ip: string): boolean {
  const now = Date.now();
  const entry = LOGIN_ATTEMPTS.get(ip);
  if (!entry) return false;
  if (now - entry.firstAt > 5 * 60 * 1000) {
    LOGIN_ATTEMPTS.delete(ip);
    return false;
  }
  return entry.count >= 20;
}
function recordLoginFailure(ip: string): void {
  const now = Date.now();
  const entry = LOGIN_ATTEMPTS.get(ip);
  if (!entry || now - entry.firstAt > 5 * 60 * 1000) {
    LOGIN_ATTEMPTS.set(ip, { count: 1, firstAt: now });
  } else {
    entry.count += 1;
  }
}

// 生成签名
async function generateSignature(
  data: string,
  secret: string
): Promise<string> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(data);

  // 导入密钥
  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

// 生成签名
  const signature = await crypto.subtle.sign('HMAC', key, messageData);

  // 转换为十六进制字符串
  return Array.from(new Uint8Array(signature))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// 判断当前请求是否走 HTTPS，用于决定 Cookie 的 Secure 属性
// 仅在确定为 https 时才置为 true，http 部署保持原有行为，避免 Cookie 被浏览器丢弃
function isHttpsRequest(req: NextRequest): boolean {
  const forwardedProto = req.headers
    .get('x-forwarded-proto')
    ?.split(',')[0]
    .trim()
    .toLowerCase();
  if (forwardedProto) {
    return forwardedProto === 'https';
  }
  return req.nextUrl.protocol === 'https:';
}

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(text)
  );
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// 生成认证Cookie（带签名）
// v1.0.1：localstorage 模式只放密码摘要，不再放明文密码；
// 数据库模式签名绑定会话纪元 HMAC(username:sessionEpoch, PASSWORD)。
async function generateAuthCookie(
  username?: string,
  password?: string,
  role?: 'owner' | 'admin' | 'user',
  includePassword = false,
  sessionEpoch?: string
): Promise<string> {
  const authData: any = { role: role || 'user' };

  // 只在需要时包含密码摘要（绝不放明文）
  if (includePassword && password) {
    authData.passwordHash = await sha256Hex(password);
    authData.timestamp = Date.now();
  }

  if (username && process.env.PASSWORD) {
    authData.username = username;
    authData.sessionEpoch = sessionEpoch || '';
    const signature = await generateSignature(
      `${username}:${authData.sessionEpoch}`,
      process.env.PASSWORD
    );
    authData.signature = signature;
    authData.timestamp = Date.now();
  }

  return encodeURIComponent(JSON.stringify(authData));
}

export async function POST(req: NextRequest) {
  const useSecureCookie = isHttpsRequest(req);
  const clientIp = loginClientIp(req);
  if (isLoginRateLimited(clientIp)) {
    return NextResponse.json(
      { error: '登录尝试过于频繁，请 5 分钟后再试' },
      { status: 429 }
    );
  }
  try {
    // 本地 / localStorage 模式——仅校验固定密码
    if (STORAGE_TYPE === 'localstorage') {
      const envPassword = process.env.PASSWORD;

      // 未配置 PASSWORD 时直接放行
      if (!envPassword) {
        const response = NextResponse.json({ ok: true });

        // 清除可能存在的认证cookie
        response.cookies.set('auth', '', {
          path: '/',
          expires: new Date(0),
          sameSite: 'lax', // 改为 lax 以支持 PWA
          httpOnly: false, // PWA 需要客户端可访问
          secure: useSecureCookie, // 仅 HTTPS 下启用 Secure
        });

        return response;
      }

      const { password } = await req.json();
      if (typeof password !== 'string') {
        return NextResponse.json({ error: '密码不能为空' }, { status: 400 });
      }

      if (password !== envPassword) {
        recordLoginFailure(clientIp);
        return NextResponse.json(
          { ok: false, error: '密码错误' },
          { status: 401 }
        );
      }

      // 验证成功，设置认证cookie
      const response = NextResponse.json({ ok: true });
      const cookieValue = await generateAuthCookie(
        undefined,
        password,
        'user',
        true
      ); // localstorage 模式包含 password
      const expires = new Date();
      expires.setDate(expires.getDate() + 7); // 7天过期

      response.cookies.set('auth', cookieValue, {
        path: '/',
        expires,
        sameSite: 'lax', // 改为 lax 以支持 PWA
        httpOnly: false, // PWA 需要客户端可访问
        secure: useSecureCookie, // 仅 HTTPS 下启用 Secure
      });

      return response;
    }

    // 数据库 / redis 模式——校验用户名并尝试连接数据库
    const { username, password } = await req.json();

    if (!username || typeof username !== 'string') {
      return NextResponse.json({ error: '用户名不能为空' }, { status: 400 });
    }
    if (!password || typeof password !== 'string') {
      return NextResponse.json({ error: '密码不能为空' }, { status: 400 });
    }

    // 可能是站长，直接读环境变量
    if (
      username === process.env.USERNAME &&
      password === process.env.PASSWORD
    ) {
      // 验证成功，设置认证cookie
      const response = NextResponse.json({ ok: true });
      const ownerEpoch = await ensureSessionEpoch(username);
      const cookieValue = await generateAuthCookie(
        username,
        password,
        'owner',
        false,
        ownerEpoch
      ); // 数据库模式不包含 password
      const expires = new Date();
      expires.setDate(expires.getDate() + 7); // 7天过期

      response.cookies.set('auth', cookieValue, {
        path: '/',
        expires,
        sameSite: 'lax', // 改为 lax 以支持 PWA
        httpOnly: false, // PWA 需要客户端可访问
        secure: useSecureCookie, // 仅 HTTPS 下启用 Secure
      });

      return response;
    } else if (username === process.env.USERNAME) {
      recordLoginFailure(clientIp);
      return NextResponse.json({ error: '用户名或密码错误' }, { status: 401 });
    }

    const config = await getConfig();
    const user = config.UserConfig.Users.find((u) => u.username === username);
    if (user && user.banned) {
      return NextResponse.json({ error: '用户被封禁' }, { status: 401 });
    }

    // 校验用户密码
    try {
      const pass = await db.verifyUser(username, password);
      if (!pass) {
        recordLoginFailure(clientIp);
        return NextResponse.json(
          { error: '用户名或密码错误' },
          { status: 401 }
        );
      }

      // 验证成功，设置认证cookie
      const response = NextResponse.json({ ok: true });
      const userEpoch = await ensureSessionEpoch(username);
      const cookieValue = await generateAuthCookie(
        username,
        password,
        user?.role || 'user',
        false,
        userEpoch
      ); // 数据库模式不包含 password
      const expires = new Date();
      expires.setDate(expires.getDate() + 7); // 7天过期

      response.cookies.set('auth', cookieValue, {
        path: '/',
        expires,
        sameSite: 'lax', // 改为 lax 以支持 PWA
        httpOnly: false, // PWA 需要客户端可访问
        secure: useSecureCookie, // 仅 HTTPS 下启用 Secure
      });

      return response;
    } catch (err) {
      console.error('数据库验证失败', err);
      return NextResponse.json({ error: '数据库错误' }, { status: 500 });
    }
  } catch (error) {
    console.error('登录接口异常', error);
    return NextResponse.json({ error: '服务器错误' }, { status: 500 });
  }
}
