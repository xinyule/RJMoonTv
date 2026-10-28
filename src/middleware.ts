/* eslint-disable no-console */

import { NextRequest, NextResponse } from 'next/server';

import { getAuthInfoFromCookie } from '@/lib/auth';

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // 跳过不需要认证的路径
  if (shouldSkipAuth(pathname)) {
    return NextResponse.next();
  }

  const storageType = process.env.NEXT_PUBLIC_STORAGE_TYPE || 'localstorage';

  if (!process.env.PASSWORD) {
    // 如果没有设置密码，重定向到警告页面
    const warningUrl = new URL('/warning', request.url);
    return NextResponse.redirect(warningUrl);
  }

  // 从cookie获取认证信息
  const authInfo = getAuthInfoFromCookie(request);

  if (!authInfo) {
    return handleAuthFailure(request, pathname);
  }

  // v1.0.1：Cookie 时间戳服务端也要校验，过期（7 天）即失效，
  // 不能只靠浏览器端的 expires 属性（偷到的 Cookie 本可一直重放）。
  if (
    authInfo.timestamp &&
    (authInfo.timestamp > Date.now() + 5 * 60 * 1000 ||
      Date.now() - authInfo.timestamp > 7 * 24 * 60 * 60 * 1000)
  ) {
    return handleAuthFailure(request, pathname);
  }

  // localstorage模式：在middleware中完成验证。
  // v1.0.1 起 Cookie 里不再放明文密码，只放密码的 SHA-256 摘要；
  // 旧的明文 Cookie 登录后会重新发摘要版，旧 Cookie 直接失效。
  if (storageType === 'localstorage') {
    if (!authInfo.passwordHash) {
      return handleAuthFailure(request, pathname);
    }
    const expectedHash = await sha256Hex(process.env.PASSWORD || '');
    if (authInfo.passwordHash !== expectedHash) {
      return handleAuthFailure(request, pathname);
    }
    return NextResponse.next();
  }

  // 其他模式：只验证签名。签名现在绑定会话纪元
  // HMAC(username:sessionEpoch, PASSWORD)，旧的无纪元 Cookie 直接失效，
  // 改密/封禁/降级轮换纪元后，API 层的纪元校验会拦住旧会话。
  if (!authInfo.username || !authInfo.signature || !authInfo.sessionEpoch) {
    return handleAuthFailure(request, pathname);
  }

  const isValidSignature = await verifySignature(
    `${authInfo.username}:${authInfo.sessionEpoch}`,
    authInfo.signature,
    process.env.PASSWORD || ''
  );
  if (isValidSignature) {
    return NextResponse.next();
  }

  return handleAuthFailure(request, pathname);
}

async function sha256Hex(text: string): Promise<string> {
  const data = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// 验证签名
async function verifySignature(
  data: string,
  signature: string,
  secret: string
): Promise<boolean> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const messageData = encoder.encode(data);

  try {
    // 导入密钥
    const key = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['verify']
    );

    // 将十六进制字符串转换为Uint8Array
    const signatureBuffer = new Uint8Array(
      signature.match(/.{1,2}/g)?.map((byte) => parseInt(byte, 16)) || []
    );

    // 验证签名
    return await crypto.subtle.verify(
      'HMAC',
      key,
      signatureBuffer,
      messageData
    );
  } catch (error) {
    console.error('签名验证失败:', error);
    return false;
  }
}

// 处理认证失败的情况
function handleAuthFailure(
  request: NextRequest,
  pathname: string
): NextResponse {
  // 如果是 API 路由，返回 401 状态码
  if (pathname.startsWith('/api')) {
    return new NextResponse('Unauthorized', { status: 401 });
  }

  // 否则重定向到登录页面
  const loginUrl = new URL('/login', request.url);
  // 保留完整的URL，包括查询参数
  const fullUrl = `${pathname}${request.nextUrl.search}`;
  loginUrl.searchParams.set('redirect', fullUrl);
  return NextResponse.redirect(loginUrl);
}

// 判断是否需要跳过认证的路径
function shouldSkipAuth(pathname: string): boolean {
  const skipPaths = [
    '/_next',
    '/favicon.ico',
    '/robots.txt',
    '/manifest.json',
    '/icons/',
    '/logo.png',
    '/screenshot.png',
  ];

  return skipPaths.some((path) => pathname.startsWith(path));
}

// 配置middleware匹配规则
export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|login|warning|api/login|api/register|api/logout|api/cron|api/server-config).*)',
  ],
};
