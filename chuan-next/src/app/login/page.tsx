import type { Metadata } from 'next';
import LoginForm from './LoginForm';

export const metadata: Metadata = {
  title: '登录 - 文件传输',
  description: '账号登录 · 首次使用请设置密码并保存找回码',
};

export default function LoginPage() {
  return <LoginForm />;
}
