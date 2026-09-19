import { useState } from 'react';
import { useAPI } from '../useAPI';

type ExplainBody = {
  question: string;
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
