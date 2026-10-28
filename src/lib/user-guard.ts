/* eslint-disable @typescript-eslint/no-explicit-any */
import { NextRequest } from 'next/server';

import { getAuthInfoFromCookie } from '@/lib/auth';
import { getConfig, setCachedConfig } from '@/lib/config';
import { db } from '@/lib/db';

/**
 * v1.0.1 新增：API 层的用户存活校验。
 *
 * 中间件跑在 Edge 层、读不到数据库，所以它只能验签名和过期，
 * 封禁 / 删号 / 纪元轮换必须在这里查配置：
 * - localstorage 模式：中间件已验过密码摘要，这里直接放行
 *   （该模式本来就没有服务端用户表，username 为空是正常情况）。
 * - 数据库模式：必须有 username、未被封禁、用户仍存在、
 *   Cookie 带 sessionEpoch，且配置里的纪元为空（重置/迁移）
 *   或与 Cookie 一致；否则一律 401，客户端会跳回登录页。
 */
export async function getActiveUser(request: NextRequest): Promise<{
  allowed: boolean;
  username: string | null;
}> {
  const storageType = process.env.NEXT_PUBLIC_STORAGE_TYPE || 'localstorage';
  const authInfo = getAuthInfoFromCookie(request);
  if (storageType === 'localstorage') {
    return { allowed: true, username: authInfo?.username || null };
  }
  if (!authInfo || !authInfo.username || !authInfo.sessionEpoch) {
    return { allowed: false, username: null };
  }
  const username = authInfo.username;
  try {
    const config = await getConfig();
    const entry = config.UserConfig.Users.find((u) => u.username === username);
    if (!entry) return { allowed: false, username: null };
    if (entry.banned) return { allowed: false, username: null };
    if (entry.sessionEpoch && entry.sessionEpoch !== authInfo.sessionEpoch) {
      return { allowed: false, username: null };
    }
    return { allowed: true, username };
  } catch {
    return { allowed: false, username: null };
  }
}

export function isEpochValid(
  entry: { sessionEpoch?: string } | undefined,
  authInfo: { sessionEpoch?: string } | null
): boolean {
  if (!entry || !authInfo?.sessionEpoch) return false;
  if (!entry.sessionEpoch) return true; // 配置被重置/迁移后首次放行，登录会重建纪元
  return entry.sessionEpoch === authInfo.sessionEpoch;
}

/** 轮换某用户的会话纪元（改密/封禁/降级后调用），旧 Cookie 立即失效。 */
export async function bumpSessionEpoch(username: string): Promise<string> {
  const epoch =
    typeof crypto !== 'undefined' && 'randomUUID' in crypto
      ? crypto.randomUUID()
      : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
  const config = await getConfig();
  const entry = config.UserConfig.Users.find((u) => u.username === username);
  if (entry) {
    entry.sessionEpoch = epoch;
    await db.saveAdminConfig(config);
    await setCachedConfig(config);
  }
  return epoch;
}

/** 登录时取用或新建某用户的会话纪元，并落盘。 */
export async function ensureSessionEpoch(username: string): Promise<string> {
  const config = await getConfig();
  let entry = config.UserConfig.Users.find((u) => u.username === username);
  if (!entry) {
    entry = { username, role: username === process.env.USERNAME ? 'owner' : 'user' } as any;
    config.UserConfig.Users.push(entry);
  }
  if (!entry.sessionEpoch) {
    entry.sessionEpoch =
      typeof crypto !== 'undefined' && 'randomUUID' in crypto
        ? crypto.randomUUID()
        : `${Date.now()}-${Math.random().toString(36).slice(2)}`;
    await db.saveAdminConfig(config);
    await setCachedConfig(config);
  }
  return entry.sessionEpoch;
}
