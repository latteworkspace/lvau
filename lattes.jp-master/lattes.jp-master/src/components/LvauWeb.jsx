import React, { useState, useEffect, useRef } from 'react';
import './LvauWeb.css';

const MAX_UPLOAD_MB = 100;

export const LvauWeb = ({ lang = 'en' }) => {
  const [health, setHealth] = useState(null);
  const [mode, setMode] = useState('encrypt');
  const [file, setFile] = useState(null);
  const [password, setPassword] = useState('');
  const [profile, setProfile] = useState('balanced');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [inspectResult, setInspectResult] = useState(null);
  
  const abortControllerRef = useRef(null);

  useEffect(() => {
    fetch('/api/lvau/health')
      .then(res => setHealth(res.ok))
      .catch(() => setHealth(false));
  }, []);

  const handleModeChange = (m) => {
    setMode(m);
    setPassword('');
    setError(null);
    setInspectResult(null);
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files.length > 0) {
      setFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleSubmit = async (e) => {
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
    } catch (e) {
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
    warningTitle: lang === 'ja' ? '⚠️ セキュリティ警告 (Server API Mode)' : '⚠️ Security Warning (Server API Mode)',
    warningText: lang === 'ja' 
      ? 'サーバーAPIモードはE2EEではありません。ファイルはHTTPS経由で送信され、APIサーバー上で処理されます。機密性の高いファイルにはローカルCLI/GUI版を使用してください。'
      : 'Server API mode is NOT E2EE. Files are transmitted over HTTPS and processed on the API server. For highly sensitive files, use the local CLI/GUI version.',
    serverStatus: lang === 'ja' ? 'APIサーバー状態: ' : 'API Server Status: ',
    online: lang === 'ja' ? 'オンライン' : 'Online',
    offline: lang === 'ja' ? 'オフライン' : 'Offline',
    encrypt: lang === 'ja' ? '暗号化' : 'Encrypt',
    decrypt: lang === 'ja' ? '復号' : 'Decrypt',
    inspect: lang === 'ja' ? '検査 (Inspect)' : 'Inspect',
    selectFile: lang === 'ja' ? 'ファイルを選択、またはドロップ' : 'Select or drop a file',
    password: lang === 'ja' ? 'マスターパスワード' : 'Master Password',
    profile: lang === 'ja' ? 'セキュリティプロファイル' : 'Security Profile',
    submit: lang === 'ja' ? '実行を開始' : 'Execute',
    cancel: lang === 'ja' ? 'キャンセル' : 'Cancel',
    loading: lang === 'ja' ? '処理中...' : 'Processing...',
  };

  return (
    <div className="lvau-container">
      <div className="lvau-warning">
        <h4>{t.warningTitle}</h4>
        <p>{t.warningText}</p>
      </div>

      <div className="lvau-status">
        {t.serverStatus} 
        <span className={`status-indicator ${health === null ? 'status-unknown' : (health ? 'status-online' : 'status-offline')}`}></span>
        <span style={{ color: health ? 'var(--success-color)' : 'var(--danger-accent)' }}>
          {health === null ? '...' : (health ? t.online : t.offline)}
        </span>
      </div>

      <div className="lvau-tabs">
        {['encrypt', 'decrypt', 'inspect'].map(m => (
          <button 
            key={m} 
            type="button"
            className={`lvau-tab ${mode === m ? 'active' : ''}`}
            onClick={() => handleModeChange(m)}
          >
            {t[m]}
          </button>
        ))}
      </div>

      <form className="lvau-form" onSubmit={handleSubmit}>
        <div className="form-group">
          <div className="file-input-wrapper">
            <input type="file" required onChange={handleFileChange} />
            <div className="file-input-content">
              <span className="icon">📁</span>
              <div>{file ? t.selectFile.replace('、またはドロップ', 'を変更') : t.selectFile}</div>
              {file && <div className="file-name-display">{file.name} ({(file.size / 1024 / 1024).toFixed(2)} MB)</div>}
            </div>
          </div>
        </div>

        {mode !== 'inspect' && (
          <div className="form-group">
            <label>{t.password}</label>
            <input 
              className="lvau-input"
              type="password" 
              required 
              value={password} 
              onChange={e => setPassword(e.target.value)}
              placeholder="••••••••••••"
            />
          </div>
        )}

        {mode === 'encrypt' && (
          <div className="form-group">
            <label>{t.profile}</label>
            <select 
              className="lvau-input"
              value={profile} 
              onChange={e => setProfile(e.target.value)}
            >
              <option value="fast">Fast (Lower memory/CPU)</option>
              <option value="balanced">Balanced (Recommended)</option>
              <option value="archive">Archive (High memory/CPU)</option>
              <option value="paranoid">Paranoid (Extreme)</option>
            </select>
          </div>
        )}

        {error && <div className="error-message">{error}</div>}

        <div className="button-group">
          <button 
            type="submit" 
            className="btn btn-primary"
            disabled={loading || health === false}
          >
            {loading ? (
              <>
                <span className="spinner"></span> {t.loading}
              </>
            ) : t.submit}
          </button>
          
          {loading && (
            <button 
              type="button" 
              className="btn btn-danger"
              onClick={handleCancel}
            >
              {t.cancel}
            </button>
          )}
        </div>
      </form>

      {inspectResult && (
        <div className="inspect-result">
          <pre>{JSON.stringify(inspectResult, null, 2)}</pre>
        </div>
      )}
    </div>
  );
};
