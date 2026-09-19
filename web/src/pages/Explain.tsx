import { useState } from 'react';
import { useAPI } from '../useAPI';

type Finding = { cause: string; confidence: string; summary: string; evidence?: string[] };

type ExplainBody = {
  question: string;
  findings?: Finding[];
  basis?: string;
  evidence: string[];
  missing: string[];
  vm: { name?: string };
};

export default function Explain() {
  const [vm, setVM] = useState('payment-prod-03');
  const { data, err } = useAPI<ExplainBody>(`/api/v1/explain?vm=${encodeURIComponent(vm)}`);
  return (
    <div>
      <div className="toolbar">
        <label>
          VM
          <input value={vm} onChange={(e) => setVM(e.target.value)} aria-label="VM to explain" />
        </label>
      </div>
      {err && <p className="warning">{err}</p>}
      <div className="grid">
        {(data?.findings || []).length > 0 && (
          <section className="card span2">
            <p className="eyebrow">FINDINGS</p>
            <h3>Where to look, best supported first</h3>
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
