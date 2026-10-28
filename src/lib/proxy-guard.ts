/**
 * 代理接口的通用安全校验（v1.0.1 修复）。
 *
 * 此前的问题：
 * - 直播代理（m3u8/segment/key/logo/precheck）只校验 source key 是否存在，
 *   对 url 本身不做任何限制，且 fetch 默认跟随重定向，导致已登录普通用户
 *   可以用服务器去请求内网 / 云元数据（169.254.169.254 等）。
 * - 豆瓣图片代理只看字面 hostname：公网 URL 302 跳到内网、或域名解析到
 *   内网 IP，都能绕过。
 *
 * 修复后（默认）：
 * - 只允许 http/https；
 * - 字面内网、DNS 解析出的内网、重定向目标的内网，一律拦截；
 * - 局域网 IPTV 确实需要代理内网时，必须由部署者显式设置
 *   PROXY_ALLOW_PRIVATE=true，并自行承担 SSRF 风险，默认不开启。
 *   图片代理（豆瓣）永远不放行内网。
 */

// 仅允许通过代理转发的图片 Content-Type
export function isImageContentType(contentType: string | null): boolean {
  if (!contentType) return false;
  return contentType.trim().toLowerCase().startsWith('image/');
}

function isPrivateIPv4(ip: string): boolean {
  const m = ip.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 192 && b === 0) return true;
  if (a === 198 && (b === 18 || b === 19)) return true;
  if (a === 100 && b >= 64 && b <= 127) return true;
  if (a >= 240) return true;
  return false;
}

function isPrivateIPv6(host: string): boolean {
  const h = host.toLowerCase();
  if (h === '::1' || h === '::') return true;
  if (/^f[cd][0-9a-f]{2}:/.test(h)) return true;
  if (/^fe[89ab][0-9a-f]:/.test(h) || h.startsWith('fe80:')) return true;
  const mapped = h.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateIPv4(mapped[1]);
  return false;
}

export function isPrivateIP(host: string): boolean {
  const h = host.toLowerCase().replace(/^\[|\]$/g, '');
  if (isPrivateIPv4(h)) return true;
  if (h.includes(':')) return isPrivateIPv6(h);
  return false;
}

function isPrivateHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (
    host === 'localhost' ||
    host.endsWith('.localhost') ||
    host.endsWith('.local') ||
    host.endsWith('.internal')
  ) {
    return true;
  }
  return isPrivateIP(host);
}

async function resolvesToPrivate(hostname: string): Promise<boolean> {
  if (isPrivateIP(hostname)) return true;
  try {
    const dns = await import('node:dns/promises');
    const addrs = await dns.lookup(hostname, { all: true });
    return addrs.some((a: { address: string }) => isPrivateIP(a.address));
  } catch {
    return false;
  }
}

export async function checkProxyTarget(
  rawUrl: string,
  allowPrivate = false
): Promise<string | null> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return '无效的地址';
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return '不支持的协议';
  }
  if (!allowPrivate) {
    if (isPrivateHostname(parsed.hostname)) {
      return '不允许代理内网地址';
    }
    if (await resolvesToPrivate(parsed.hostname)) {
      return '域名解析到内网地址';
    }
  }
  return null;
}

export function checkImageProxyTarget(rawUrl: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return '无效的图片地址';
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return '不支持的协议';
  }
  if (isPrivateHostname(parsed.hostname)) {
    return '不允许代理内网地址';
  }
  return null;
}

export function proxyAllowPrivate(): boolean {
  return process.env.PROXY_ALLOW_PRIVATE === 'true';
}

export async function fetchValidated(
  rawUrl: string,
  init: RequestInit,
  allowPrivate = false,
  timeoutMs?: number
): Promise<Response> {
  let current = rawUrl;
  for (let hop = 0; hop <= 5; hop++) {
    const invalid = await checkProxyTarget(current, allowPrivate);
    if (invalid) {
      throw new Error(invalid);
    }
    const signal =
      timeoutMs != null
        ? AbortSignal.timeout(timeoutMs)
        : init.signal || undefined;
    const response = await fetch(current, {
      ...init,
      redirect: 'manual',
      signal,
    });
    const location = response.headers.get('location');
    if (
      [301, 302, 303, 307, 308].includes(response.status) &&
      location
    ) {
      const next = new URL(location, current).toString();
      try {
        response.body?.cancel();
      } catch {
        // ignore
      }
      current = next;
      continue;
    }
    return response;
  }
  throw new Error('重定向次数过多');
}
