import { useState } from 'react';
import { api } from '../api';
import VMInput from '../components/VMInput';
import { atFromInput, explainPath, incidentFileName, incidentPath, LIVE_WINDOWS, PAST_WINDOWS } from '../explainQuery';
import { LIVE_MS, useAPI } from '../useAPI';
import { useVMName } from '../useVMName';

type Finding = { cause: string; confidence: string; summary: string; evidence?: string[] };

type ExplainBody = {
  question: string;
  window?: string;
  at?: string;
  resolution?: string;
  findings?: Finding[];
  basis?: string;
  evidence: string[];
  missing: string[];
  vm: { name?: string };
};

export default function Explain() {
  const { vm, setVM, names } = useVMName();
  const [liveWindow, setLiveWindow] = useState('60s');
  const [pastWindow, setPastWindow] = useState('15m');
  const [atInput, setAtInput] = useState('');
  const at = atFromInput(atInput);
  const window = at === '' ? liveWindow : pastWindow;
  // A past verdict is built from stored snapshots and does not change, so it is fetched once, not polled.
  const { data, err } = useAPI<ExplainBody>(explainPath(vm, window, at), { refreshMs: at === '' ? LIVE_MS : 0 });
  const [saving, setSaving] = useState('');

  async function downloadIncident() {
    setSaving('');
    try {
      const bundle = await api<unknown>(incidentPath(vm, window, at));
      const url = URL.createObjectURL(new Blob([JSON.stringify(bundle, null, 2)], { type: 'application/json' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = incidentFileName(vm, at);
      a.click();
      URL.revokeObjectURL(url);
      setSaving('Saved. It names VMs, addresses and DNS names: treat it like the event list.');
    } catch (e) {
      setSaving(String(e));
    }
  }
  return (
    <div>
      <div className="toolbar">
        <label>
          VM
          <VMInput value={vm} names={names} onChange={setVM} label="VM to explain" />
        </label>
        <label>
          At
          <input type="datetime-local" value={atInput} onChange={(e) => setAtInput(e.target.value)} aria-label="Explain at a past time" />
        </label>
        <label>
          Look back
          <select
            value={window}
            onChange={(e) => (at === '' ? setLiveWindow(e.target.value) : setPastWindow(e.target.value))}
            aria-label="How far back to look"
          >
            {(at === '' ? LIVE_WINDOWS : PAST_WINDOWS).map((w) => (
              <option key={w.value} value={w.value}>
                {w.label}
              </option>
            ))}
          </select>
        </label>
        {atInput !== '' && (
          <button type="button" onClick={() => setAtInput('')}>
            Back to now
          </button>
        )}
        <button type="button" onClick={downloadIncident} disabled={vm === ''}>
          Download incident bundle
        </button>
      </div>
      {err && <p className="warning">{err}</p>}
      {saving && <p className="hint">{saving}</p>}
      <div className="grid">
        {(data?.findings || []).length > 0 && (
          <section className="card span2">
            <p className="eyebrow">FINDINGS</p>
            <h3>Where to look, best supported first</h3>
            {data?.at ? (
              <p className="finding-basis">
                Looking at: {data.window === 'none' ? 'nothing stored' : `${data.window} ending ${data.at}`}
                {data.resolution ? ` (${data.resolution})` : ''}
              </p>
            ) : (
              data?.window && <p className="finding-basis">Looking at: {data.window === 'lifetime' ? 'everything since the daemon attached' : `the last ${data.window}`}</p>
            )}
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
