/**
 * 账号相关接口封装
 *
 * 所有请求都带 credentials: 'include'，因为登录态是 HttpOnly Cookie。
 * 前后端同域部署（Go 内嵌前端 / Nginx 反代）时天然可用；
 * 若前后端分离部署，需要在反向代理层把 /api 与页面收敛到同一域名，
 * 否则浏览器的跨站策略会拦下 Cookie。
 */

import { getDirectBackendUrl } from './config';

export interface AuthStatus {
  initialized: boolean;
  loggedIn: boolean;
  username?: string;
}

export interface AuthResult {
  success: boolean;
  username?: string;
  /** 仅初始化与重置密码时返回，明文只出现这一次 */
  recoveryCode?: string;
  message?: string;
}

export class AuthError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'AuthError';
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(getDirectBackendUrl(path), {
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
      ...init,
    });
  } catch {
    throw new AuthError('无法连接服务器，请检查网络或服务是否在运行', 0);
  }

  let data: any = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }

  if (!res.ok || data?.success === false) {
    const msg = data?.message || `请求失败（HTTP ${res.status}）`;
    throw new AuthError(msg, res.status);
  }
  return data as T;
}

/** 查询账号状态：是否已初始化、当前是否已登录 */
export async function fetchAuthStatus(): Promise<AuthStatus> {
  const data = await request<any>('/api/auth/status', { method: 'GET' });
  return {
    initialized: Boolean(data?.initialized),
    loggedIn: Boolean(data?.loggedIn),
    username: data?.username,
  };
}

/** 首次初始化账号（仅当服务端尚未初始化时可用），返回一次性找回码 */
export async function setupAccount(username: string, password: string): Promise<AuthResult> {
  return request<AuthResult>('/api/auth/setup', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
}

/** 账号密码登录 */
export async function login(username: string, password: string): Promise<AuthResult> {
  return request<AuthResult>('/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });
}

/** 退出登录 */
export async function logout(): Promise<void> {
  await request('/api/auth/logout', { method: 'POST', body: '{}' });
}

/** 凭找回码重置密码，成功后返回新的找回码（旧码立即失效） */
export async function resetPassword(recoveryCode: string, newPassword: string): Promise<AuthResult> {
  return request<AuthResult>('/api/auth/reset', {
    method: 'POST',
    body: JSON.stringify({ recoveryCode, newPassword }),
  });
}

/** 密码强度前端预校验，与服务端规则保持一致 */
export function validatePassword(password: string): string | null {
  if (password.length < 8) return '密码至少 8 位';
  if (password.length > 128) return '密码不能超过 128 位';
  if (!password.trim()) return '密码不能全是空格';
  return null;
}

/** 读取登录后需要回跳的路径，默认首页 */
export function getRedirectTarget(): string {
  if (typeof window === 'undefined') return '/';
  const next = new URLSearchParams(window.location.search).get('next');
  // 只允许站内相对路径，避免开放重定向
  if (!next || !next.startsWith('/') || next.startsWith('//')) return '/';
  return next;
}
