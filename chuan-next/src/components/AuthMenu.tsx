'use client';

import { useCallback, useEffect, useState } from 'react';
import { Loader2, LogOut, User } from 'lucide-react';

import { fetchAuthStatus, logout } from '@/lib/auth';

/**
 * 首页右上角的登录态入口：显示当前用户名，提供退出登录。
 * 未登录时理论上进不到首页（服务端已拦截），这里返回 null 兜底。
 */
export default function AuthMenu() {
  const [username, setUsername] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetchAuthStatus()
      .then((status) => {
        if (!cancelled) setUsername(status.username || '');
      })
      .catch(() => {
        /* 状态拉取失败不阻塞主界面 */
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const handleLogout = useCallback(async () => {
    setBusy(true);
    try {
      await logout();
    } catch {
      /* 即使请求失败也跳登录页，避免用户卡住 */
    } finally {
      window.location.href = '/login';
    }
  }, []);

  if (!username) return null;

  return (
    <div className="mb-2 flex items-center justify-end gap-2 text-sm">
      <span className="inline-flex items-center gap-1.5 rounded-full border border-slate-200 bg-white/70 px-3 py-1 text-slate-600 backdrop-blur">
        <User className="h-3.5 w-3.5" />
        <span className="max-w-[10rem] truncate">{username}</span>
      </span>
      <button
        type="button"
        onClick={handleLogout}
        disabled={busy}
        className="inline-flex items-center gap-1.5 rounded-full border border-slate-200 bg-white/70 px-3 py-1 text-slate-500 transition-colors hover:border-red-200 hover:text-red-600 disabled:opacity-60"
      >
        {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <LogOut className="h-3.5 w-3.5" />}
        退出
      </button>
    </div>
  );
}
