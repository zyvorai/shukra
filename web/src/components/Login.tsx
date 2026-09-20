import { useState } from 'react';
import { probe, setToken } from '../api';

export default function Login({ onLogin, initialError = '' }: { onLogin: () => void; initialError?: string }) {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [error, setError] = useState(initialError);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError('');
    const result = await probe(password);
    setBusy(false);
    if (result === 'ok') {
      setToken(password);
      onLogin();
      return;
    }
    setToken('');
    setError(result === 'unauthorized' ? 'Wrong username or password.' : 'Could not reach shukrad. Check the URL and try again.');
  }

  return (
    <div className="login-shell">
      <div className="login-info">
        <img src="/zyvor-mark.svg" alt="" className="login-logo" />
        <p className="eyebrow">Shukra · Zyvor</p>
        <h1>Shukra.</h1>
        <p>eBPF-powered runtime intelligence and security for KVM. Observe, protect, and explain every workload from the host.</p>
        <p className="login-host">
          Daemon <code>{window.location.host}</code>
        </p>
      </div>
      <form className="card login-card" onSubmit={submit}>
        <p className="eyebrow">Sign in</p>
        <h1>Shukra</h1>
        {error && <p className="login-error">{error}</p>}
        <label className="tokenbox">
          Username
          <input value={username} onChange={(e) => setUsername(e.target.value)} autoComplete="username" />
        </label>
        <label className="tokenbox">
          API token
          <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
        </label>
        <button className="primary" type="submit" disabled={busy}>
          {busy ? 'Checking…' : 'Continue'}
        </button>
      </form>
    </div>
  );
}
