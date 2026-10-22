import React, { useEffect, useState } from 'react';
import { useStore } from '../store';
import Modal from './Modal';

// Global {{var}} fill prompt for snippets — driven by store.varPrompt so it
// works identically from the terminal dropdown, the Snippets page and the
// command palette.
export default function SnippetVarPrompt() {
  const vp = useStore((s) => s.varPrompt);
  const submitVarPrompt = useStore((s) => s.submitVarPrompt);
  const closeVarPrompt = useStore((s) => s.closeVarPrompt);
  const [values, setValues] = useState({});

  useEffect(() => {
    setValues({});
  }, [vp?.snippet?.id, vp?.tabId]);

  if (!vp) return null;

  const submit = (e) => {
    e.preventDefault();
    submitVarPrompt(values);
  };

  return (
    <Modal title={`Fill: ${vp.snippet.name}`} onClose={closeVarPrompt}>
      <form onSubmit={submit} className="space-y-3">
        {vp.vars.map((v) => (
          <div key={v}>
            <label className="label font-mono">{`{{${v}}}`}</label>
            <input
              className="input font-mono"
              autoFocus={v === vp.vars[0]}
              value={values[v] || ''}
              onChange={(e) => setValues((s) => ({ ...s, [v]: e.target.value }))}
            />
          </div>
        ))}
        <div className="flex justify-end gap-2">
          <button type="button" className="btn-ghost" onClick={closeVarPrompt}>
            Cancel
          </button>
          <button className="btn-primary">{vp.execute ? 'Run' : 'Insert'}</button>
        </div>
      </form>
    </Modal>
  );
}
