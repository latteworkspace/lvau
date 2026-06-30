import React, { useState, useEffect, useRef } from 'react';

const MAX_UPLOAD_MB = 100;

export const LvauWeb: React.FC<{ lang?: 'en' | 'ja' }> = ({ lang = 'en' }) => {
  const [health, setHealth] = useState<boolean | null>(null);
  const [mode, setMode] = useState<'encrypt' | 'decrypt' | 'inspect'>('encrypt');
  const [file, setFile] = useState<File | null>(null);
  const [password, setPassword] = useState('');
  const [profile, setProfile] = useState('balanced');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [inspectResult, setInspectResult] = useState<any>(null);
  
  const abortControllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    fetch('/api/lvau/health')
      .then(res => setHealth(res.ok))
      .catch(() => setHealth(false));
  }, []);

  const handleModeChange = (m: typeof mode) => {
    setMode(m);
    setPassword('');
    setError(null);
    setInspectResult(null);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!file) return;

    if (file.size > MAX_UPLOAD_MB * 1024 * 1024) {
      setError(`File size exceeds ${MAX_UPLOAD_MB}MB limit.`);
      return;
    }

    setLoading(true);
    setError(null);
    setInspectResult(null);

    const formData = new FormData();
    formData.append('file', file);
    if (mode !== 'inspect') {
      formData.append('password', password);
    }
    if (mode === 'encrypt') {
      formData.append('profile', profile);
    }

    abortControllerRef.current = new AbortController();

    try {
      const res = await fetch(`/api/lvau/${mode}`, {
        method: 'POST',
        body: formData,
        signal: abortControllerRef.current.signal,
      });

      if (!res.ok) {
        let errMessage = 'An unknown error occurred';
        try {
          const err = await res.json();
          errMessage = err.message || err.code || errMessage;
        } catch {
          errMessage = `Server error: ${res.status} ${res.statusText}`;
        }
        setError(errMessage);
        setLoading(false);
        return;
      }

      if (mode === 'inspect') {
        const data = await res.json();
        setInspectResult(data);
      } else {
        const blob = await res.blob();
        
        // Extract filename from header if available
        let filename = mode === 'encrypt' ? 'encrypted.lvau' : 'decrypted.bin';
        const disposition = res.headers.get('Content-Disposition');
        if (disposition && disposition.includes('filename="')) {
          const match = disposition.match(/filename="(.+?)"/);
          if (match && match[1]) filename = match[1];
        }

        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
        
        setPassword('');
      }
    } catch (e: any) {
      if (e.name === 'AbortError') {
        setError('Request cancelled or timed out.');
      } else {
        setError(e.message || 'Network error');
      }
    } finally {
      setLoading(false);
      abortControllerRef.current = null;
    }
  };

  const handleCancel = () => {
    if (abortControllerRef.current) {
      abortControllerRef.current.abort();
    }
  };

  const t = {
    warningTitle: lang === 'ja' ? '⚠️ 重要なセキュリティ警告 (Server API Mode)' : '⚠️ Important Security Warning (Server API Mode)',
    warningText: lang === 'ja' 
      ? 'サーバーAPIモードはエンドツーエンド暗号化（E2EE）ではありません。ファイルとパスワードはHTTPS経由で送信され、APIサーバー（Oracle Cloud）のメモリ上で処理されます。機密性の高いファイルの処理には、オフラインで動作するローカルの CLI/GUI 版を使用してください。'
      : 'Server API mode is NOT End-to-End Encrypted (E2EE). Files and passwords are transmitted over HTTPS and processed in memory on the API server (Oracle Cloud). For highly sensitive files, use the offline local CLI/GUI version.',
    serverStatus: lang === 'ja' ? 'APIサーバー状態: ' : 'API Server Status: ',
    online: lang === 'ja' ? 'オンライン' : 'Online',
    offline: lang === 'ja' ? 'オフライン' : 'Offline',
    encrypt: lang === 'ja' ? '暗号化' : 'Encrypt',
    decrypt: lang === 'ja' ? '復号' : 'Decrypt',
    inspect: lang === 'ja' ? 'メタデータ検査' : 'Inspect Metadata',
    selectFile: lang === 'ja' ? 'ファイルを選択' : 'Select File',
    password: lang === 'ja' ? 'パスワード' : 'Password',
    profile: lang === 'ja' ? 'セキュリティプロファイル' : 'Security Profile',
    submit: lang === 'ja' ? '実行' : 'Submit',
    cancel: lang === 'ja' ? 'キャンセル' : 'Cancel',
    loading: lang === 'ja' ? '処理中...' : 'Processing...',
  };

  return (
    <div style={{ maxWidth: '600px', margin: '0 auto', fontFamily: 'sans-serif' }}>
      <div style={{ padding: '16px', backgroundColor: '#fff3cd', color: '#856404', borderRadius: '8px', marginBottom: '24px' }}>
        <h4 style={{ margin: '0 0 8px 0' }}>{t.warningTitle}</h4>
        <p style={{ margin: 0, fontSize: '14px' }}>{t.warningText}</p>
      </div>

      <div style={{ marginBottom: '16px', fontWeight: 'bold' }}>
        {t.serverStatus} 
        <span style={{ color: health ? 'green' : 'red' }}>
          {health === null ? '...' : (health ? t.online : t.offline)}
        </span>
      </div>

      <div style={{ display: 'flex', gap: '8px', marginBottom: '24px' }}>
        {(['encrypt', 'decrypt', 'inspect'] as const).map(m => (
          <button 
            key={m} 
            onClick={() => handleModeChange(m)}
            style={{ 
              fontWeight: mode === m ? 'bold' : 'normal',
              padding: '8px 16px',
              cursor: 'pointer'
            }}
          >
            {t[m]}
          </button>
        ))}
      </div>

      <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
        <div>
          <label style={{ display: 'block', marginBottom: '4px' }}>{t.selectFile}</label>
          <input type="file" required onChange={e => setFile(e.target.files?.[0] || null)} />
        </div>

        {mode !== 'inspect' && (
          <div>
            <label style={{ display: 'block', marginBottom: '4px' }}>{t.password}</label>
            <input 
              type="password" 
              required 
              value={password} 
              onChange={e => setPassword(e.target.value)} 
              style={{ padding: '8px', width: '100%' }}
            />
          </div>
        )}

        {mode === 'encrypt' && (
          <div>
            <label style={{ display: 'block', marginBottom: '4px' }}>{t.profile}</label>
            <select value={profile} onChange={e => setProfile(e.target.value)} style={{ padding: '8px', width: '100%' }}>
              <option value="fast">Fast</option>
              <option value="balanced">Balanced</option>
              <option value="archive">Archive</option>
              <option value="paranoid">Paranoid</option>
            </select>
          </div>
        )}

        {error && <div style={{ color: 'red', marginTop: '8px' }}>{error}</div>}

        <div style={{ display: 'flex', gap: '8px' }}>
          <button 
            type="submit" 
            disabled={loading || health === false}
            style={{ flex: 1, padding: '12px', backgroundColor: '#0056b3', color: 'white', border: 'none', borderRadius: '4px', cursor: (loading || health === false) ? 'not-allowed' : 'pointer' }}
          >
            {loading ? t.loading : t.submit}
          </button>
          
          {loading && (
            <button 
              type="button" 
              onClick={handleCancel}
              style={{ padding: '12px', backgroundColor: '#dc3545', color: 'white', border: 'none', borderRadius: '4px', cursor: 'pointer' }}
            >
              {t.cancel}
            </button>
          )}
        </div>
      </form>

      {inspectResult && (
        <div style={{ marginTop: '24px', padding: '16px', backgroundColor: '#f8f9fa', borderRadius: '8px' }}>
          <pre>{JSON.stringify(inspectResult, null, 2)}</pre>
        </div>
      )}
    </div>
  );
};
