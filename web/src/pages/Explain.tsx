import { useState } from 'react';
import VMInput from '../components/VMInput';
import { LIVE_MS, useAPI } from '../useAPI';
import { useVMName } from '../useVMName';

type Finding = { cause: string; confidence: string; summary: string; evidence?: string[] };

type ExplainBody = {
  question: string;
  window?: string;
  findings?: Finding[];
  basis?: string;
  evidence: string[];
  missing: string[];
  vm: { name?: string };
};

export default function Explain() {
  const { vm, setVM, names } = useVMName();
  const [window, setWindow] = useState('60s');
  const { data, err } = useAPI<ExplainBody>(`/api/v1/explain?vm=${encodeURIComponent(vm)}&window=${window}`, { refreshMs: LIVE_MS });
  return (
    <div>
      <div className="toolbar">
        <label>
          VM
          <VMInput value={vm} names={names} onChange={setVM} label="VM to explain" />
        </label>
        <label>
          Look back
          <select value={window} onChange={(e) => setWindow(e.target.value)} aria-label="How far back to look">
            <option value="60s">last minute</option>
            <option value="5m">last 5 minutes</option>
            <option value="lifetime">since the daemon attached</option>
          </select>
        </label>
      </div>
      {err && <p className="warning">{err}</p>}
      <div className="grid">
        {(data?.findings || []).length > 0 && (
          <section className="card span2">
            <p className="eyebrow">FINDINGS</p>
            <h3>Where to look, best supported first</h3>
            {data?.window && <p className="finding-basis">Looking at: {data.window === 'lifetime' ? 'everything since the daemon attached' : `the last ${data.window}`}</p>}
            <ol className="findings">
              {(data?.findings || []).map((f) => (
                <li key={f.cause}>
                  <strong>{f.cause.replace(/_/g, ' ')}</strong>
                  <span className={`severity-badge conf-${f.confidence}`}>{f.confidence} confidence</span>
                  <p>{f.summary}</p>
                  {(f.evidence || []).map((e) => (
                    <p key={e} className="finding-evidence">
                      {e}
                    </p>
                  ))}
                </li>
              ))}
            </ol>
            {data?.basis && <p className="finding-basis">{data.basis}</p>}
          </section>
        )}
        <section className="card span2">
          <p className="eyebrow">EVIDENCE</p>
          <h3>{data?.question || 'why is this VM slow?'}</h3>
          <ul>
            {(data?.evidence || []).map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </section>
        <section className="card">
          <p className="eyebrow">MISSING</p>
          <h3>Not in this build</h3>
          <ul>
            {(data?.missing || []).map((line) => (
              <li key={line}>{line}</li>
            ))}
          </ul>
        </section>
      </div>
    </div>
  );
}
