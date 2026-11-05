'use client';

import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertCircle,
  ArrowLeft,
  ArrowRight,
  Check,
  Copy,
  Download,
  Eye,
  EyeOff,
  KeyRound,
  Loader2,
  LogIn,
  ShieldCheck,
} from 'lucide-react';

import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import {
  AuthError,
  fetchAuthStatus,
  getRedirectTarget,
  login,
  resetPassword,
  setupAccount,
  validatePassword,
} from '@/lib/auth';

type Phase = 'loading' | 'setup' | 'login' | 'reset' | 'showcode';

/** 统一把异常转成可展示的文案 */
function toMessage(err: unknown): string {
  if (err instanceof AuthError) return err.message;
  if (err instanceof Error) return err.message;
  return '操作失败，请重试';
}

/** 密码输入框（带显隐切换） */
function PasswordField({
  id,
  label,
  value,
  onChange,
  placeholder,
  autoComplete,
  autoFocus,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  autoComplete?: string;
  autoFocus?: boolean;
}) {
  const [visible, setVisible] = useState(false);

  return (
    <div className="space-y-1.5">
      <label htmlFor={id} className="block text-sm font-medium text-slate-700">
        {label}
      </label>
      <div className="relative">
        <Input
          id={id}
          type={visible ? 'text' : 'password'}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder={placeholder}
          autoComplete={autoComplete}
          autoFocus={autoFocus}
          className="pr-10"
        />
        <button
          type="button"
          onClick={() => setVisible((v) => !v)}
          className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-1 text-slate-400 transition-colors hover:text-slate-600"
          aria-label={visible ? '隐藏密码' : '显示密码'}
          tabIndex={-1}
        >
          {visible ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
        </button>
      </div>
    </div>
  );
}

/** 找回码展示卡片：分组大字 + 复制 + 下载 + 必须确认已保存 */
function RecoveryCodeCard({
  code,
  title,
  description,
  onContinue,
}: {
  code: string;
  title: string;
  description: string;
  onContinue: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const groups = useMemo(() => code.split('-'), [code]);

  useEffect(() => {
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, []);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(code);
    } catch {
      // 极老浏览器降级：临时 textarea + execCommand
      const ta = document.createElement('textarea');
      ta.value = code;
      ta.style.position = 'fixed';
      ta.style.opacity = '0';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    setCopied(true);
    if (timerRef.current) clearTimeout(timerRef.current);
    timerRef.current = setTimeout(() => setCopied(false), 2000);
  }, [code]);

  const handleDownload = useCallback(() => {
    const content = [
      '串流文件传输 · 账号找回码',
      '',
      `找回码：${code}`,
      '',
      '用途：忘记密码时凭此码重置密码。',
      '注意：本码只显示这一次，且使用后立即失效并换发新码；',
      '      请勿截图分享，建议存放在密码管理器或离线介质中。',
      `生成时间：${new Date().toLocaleString()}`,
      '',
    ].join('\n');
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'chuan-recovery-code.txt';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [code]);

  return (
    <div className="space-y-5">
      <div className="flex items-start gap-3">
        <div className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-amber-100">
          <KeyRound className="h-5 w-5 text-amber-600" />
        </div>
        <div>
          <h2 className="text-lg font-semibold text-slate-900">{title}</h2>
          <p className="mt-1 text-sm leading-relaxed text-slate-600">{description}</p>
        </div>
      </div>

      <div className="rounded-xl border border-amber-200 bg-amber-50 p-4">
        <div className="grid grid-cols-3 gap-2 sm:grid-cols-6">
          {groups.map((g, i) => (
            <div
              key={i}
              className="rounded-md border border-amber-300/70 bg-white py-2 text-center font-mono text-sm font-semibold tracking-wider text-slate-800 sm:text-base"
            >
              {g}
            </div>
          ))}
        </div>

        <div className="mt-3 flex flex-wrap gap-2">
          <Button type="button" variant="outline" size="sm" onClick={handleCopy}>
            {copied ? <Check className="mr-1.5 h-4 w-4 text-green-600" /> : <Copy className="mr-1.5 h-4 w-4" />}
            {copied ? '已复制' : '复制'}
          </Button>
          <Button type="button" variant="outline" size="sm" onClick={handleDownload}>
            <Download className="mr-1.5 h-4 w-4" />
            下载 .txt
          </Button>
        </div>
      </div>

      <label className="flex cursor-pointer items-start gap-2.5 rounded-lg bg-slate-50 p-3 text-sm text-slate-700">
        <input
          type="checkbox"
          checked={confirmed}
          onChange={(e) => setConfirmed(e.target.checked)}
          className="mt-0.5 h-4 w-4 accent-[hsl(var(--primary))]"
        />
        <span>
          我已把找回码保存到安全的地方。遗忘密码且丢失找回码将无法恢复账号，只能删除服务端
          <code className="mx-1 rounded bg-slate-200 px-1 py-0.5 text-xs">data/auth.json</code>
          重置。
        </span>
      </label>

      <Button type="button" onClick={onContinue} disabled={!confirmed} className="w-full">
        进入应用
        <ArrowRight className="ml-2 h-4 w-4" />
      </Button>
    </div>
  );
}

export default function LoginForm() {
  const [phase, setPhase] = useState<Phase>('loading');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [recoveryInput, setRecoveryInput] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newConfirm, setNewConfirm] = useState('');
  const [issuedCode, setIssuedCode] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  // 进页面先问服务端：已登录直接回首页，未初始化则直接进"首次设置"
  useEffect(() => {
    let cancelled = false;
    fetchAuthStatus()
      .then((status) => {
        if (cancelled) return;
        if (status.loggedIn) {
          window.location.replace(getRedirectTarget());
          return;
        }
        if (status.username) setUsername(status.username);
        setPhase(status.initialized ? 'login' : 'setup');
      })
      .catch((err) => {
        if (cancelled) return;
        setError(toMessage(err));
        setPhase('login');
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const resetForm = useCallback(() => {
    setPassword('');
    setConfirm('');
    setRecoveryInput('');
    setNewPassword('');
    setNewConfirm('');
    setError('');
  }, []);

  const switchPhase = useCallback(
    (next: Phase) => {
      resetForm();
      setPhase(next);
    },
    [resetForm]
  );

  const handleSetup = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError('');

      if (!username.trim()) return setError('请填写用户名');
      const pwErr = validatePassword(password);
      if (pwErr) return setError(pwErr);
      if (password !== confirm) return setError('两次输入的密码不一致');

      setBusy(true);
      try {
        const result = await setupAccount(username.trim(), password);
        if (!result.recoveryCode) {
          setError('服务端未返回找回码，请联系管理员检查服务');
          return;
        }
        setIssuedCode(result.recoveryCode);
        setPhase('showcode');
      } catch (err) {
        setError(toMessage(err));
      } finally {
        setBusy(false);
      }
    },
    [username, password, confirm]
  );

  const handleLogin = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError('');

      if (!username.trim() || !password) return setError('请填写用户名和密码');

      setBusy(true);
      try {
        await login(username.trim(), password);
        window.location.replace(getRedirectTarget());
      } catch (err) {
        setError(toMessage(err));
        setBusy(false);
      }
    },
    [username, password]
  );

  const handleReset = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError('');

      if (!recoveryInput.trim()) return setError('请填写找回码');
      const pwErr = validatePassword(newPassword);
      if (pwErr) return setError(pwErr);
      if (newPassword !== newConfirm) return setError('两次输入的密码不一致');

      setBusy(true);
      try {
        const result = await resetPassword(recoveryInput.trim(), newPassword);
        if (!result.recoveryCode) {
          setError('服务端未返回新的找回码，请联系管理员检查服务');
          return;
        }
        setIssuedCode(result.recoveryCode);
        setPhase('showcode');
      } catch (err) {
        setError(toMessage(err));
      } finally {
        setBusy(false);
      }
    },
    [recoveryInput, newPassword, newConfirm]
  );

  const goHome = useCallback(() => {
    window.location.replace(getRedirectTarget());
  }, []);

  const codeTitle = phase === 'showcode' ? '请保存你的找回码' : '';

  return (
    <div className="flex min-h-screen flex-col bg-gradient-to-br from-slate-50 to-blue-50">
      <div className="flex flex-1 items-center justify-center px-4 py-10">
        <div className="w-full max-w-md">
          {/* 品牌区 */}
          <div className="mb-6 text-center">
            <div className="mb-3 inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-[hsl(var(--primary))] text-white shadow-lg shadow-indigo-200">
              <ShieldCheck className="h-6 w-6" />
            </div>
            <h1 className="text-2xl font-bold tracking-tight text-slate-900">串流文件传输</h1>
            <p className="mt-1 text-sm text-slate-500">端到端传输 · 请先验证身份</p>
          </div>

          <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-xl shadow-slate-200/60 sm:p-8">
            {phase === 'loading' && (
              <div className="flex flex-col items-center gap-3 py-10 text-slate-500">
                <Loader2 className="h-6 w-6 animate-spin" />
                <span className="text-sm">正在检查登录状态...</span>
              </div>
            )}

            {error && phase !== 'loading' && (
              <div className="mb-4 flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700">
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                <span>{error}</span>
              </div>
            )}

            {phase === 'setup' && (
              <form onSubmit={handleSetup} className="space-y-4">
                <div>
                  <h2 className="text-lg font-semibold text-slate-900">首次使用，设置管理员账号</h2>
                  <p className="mt-1 text-sm text-slate-600">
                    整个服务只有一个账号。设置完成后会生成一次性找回码，用于忘记密码时重置。
                  </p>
                </div>

                <div className="space-y-1.5">
                  <label htmlFor="setup-username" className="block text-sm font-medium text-slate-700">
                    用户名
                  </label>
                  <Input
                    id="setup-username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="字母、数字、_ - . @，2~32 位"
                    autoComplete="username"
                    autoFocus
                    disabled={busy}
                  />
                </div>

                <PasswordField
                  id="setup-password"
                  label="设置密码"
                  value={password}
                  onChange={setPassword}
                  placeholder="至少 8 位，建议混合大小写与符号"
                  autoComplete="new-password"
                />

                <PasswordField
                  id="setup-confirm"
                  label="确认密码"
                  value={confirm}
                  onChange={setConfirm}
                  placeholder="再输入一次"
                  autoComplete="new-password"
                />

                <Button type="submit" disabled={busy} className="w-full">
                  {busy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-2 h-4 w-4" />}
                  {busy ? '创建中...' : '创建账号并生成找回码'}
                </Button>
              </form>
            )}

            {phase === 'login' && (
              <form onSubmit={handleLogin} className="space-y-4">
                <div>
                  <h2 className="text-lg font-semibold text-slate-900">登录</h2>
                  <p className="mt-1 text-sm text-slate-600">未登录无法创建房间或传输文件。</p>
                </div>

                <div className="space-y-1.5">
                  <label htmlFor="login-username" className="block text-sm font-medium text-slate-700">
                    用户名
                  </label>
                  <Input
                    id="login-username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="你的用户名"
                    autoComplete="username"
                    autoFocus
                    disabled={busy}
                  />
                </div>

                <PasswordField
                  id="login-password"
                  label="密码"
                  value={password}
                  onChange={setPassword}
                  placeholder="输入密码"
                  autoComplete="current-password"
                />

                <Button type="submit" disabled={busy} className="w-full">
                  {busy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <LogIn className="mr-2 h-4 w-4" />}
                  {busy ? '登录中...' : '登录'}
                </Button>

                <button
                  type="button"
                  onClick={() => switchPhase('reset')}
                  className="w-full text-center text-sm text-slate-500 underline-offset-4 hover:text-[hsl(var(--primary))] hover:underline"
                >
                  忘记密码？用找回码重置
                </button>
              </form>
            )}

            {phase === 'reset' && (
              <form onSubmit={handleReset} className="space-y-4">
                <button
                  type="button"
                  onClick={() => switchPhase('login')}
                  className="inline-flex items-center text-sm text-slate-500 hover:text-slate-700"
                >
                  <ArrowLeft className="mr-1 h-4 w-4" />
                  返回登录
                </button>

                <div>
                  <h2 className="text-lg font-semibold text-slate-900">用找回码重置密码</h2>
                  <p className="mt-1 text-sm text-slate-600">
                    找回码不区分大小写，连字符和空格可忽略。重置成功后旧码立即失效，并生成新码。
                  </p>
                </div>

                <div className="space-y-1.5">
                  <label htmlFor="recovery-code" className="block text-sm font-medium text-slate-700">
                    找回码
                  </label>
                  <Input
                    id="recovery-code"
                    value={recoveryInput}
                    onChange={(e) => setRecoveryInput(e.target.value)}
                    placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
                    className="font-mono tracking-wider"
                    autoFocus
                    disabled={busy}
                  />
                </div>

                <PasswordField
                  id="reset-password"
                  label="新密码"
                  value={newPassword}
                  onChange={setNewPassword}
                  placeholder="至少 8 位"
                  autoComplete="new-password"
                />

                <PasswordField
                  id="reset-confirm"
                  label="确认新密码"
                  value={newConfirm}
                  onChange={setNewConfirm}
                  placeholder="再输入一次"
                  autoComplete="new-password"
                />

                <Button type="submit" disabled={busy} className="w-full">
                  {busy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <KeyRound className="mr-2 h-4 w-4" />}
                  {busy ? '重置中...' : '重置密码'}
                </Button>
              </form>
            )}

            {phase === 'showcode' && issuedCode && (
              <RecoveryCodeCard
                code={issuedCode}
                title={codeTitle}
                description="这是你唯一的账号恢复凭据，本页关闭后将无法再次查看。请复制或下载后离线保存。"
                onContinue={goHome}
              />
            )}
          </div>

          <p className="mt-6 text-center text-xs text-slate-400">
            连续 5 次密码错误将锁定 3 分钟 · 会话有效期 7 天
          </p>
        </div>
      </div>
    </div>
  );
}
