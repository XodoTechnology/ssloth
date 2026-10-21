import React from 'react';
import { useStore } from '../store';

const KIND_STYLES = {
  info: 'border-ink-600 bg-ink-800 text-zinc-200',
  success: 'border-emerald-700 bg-emerald-950 text-emerald-200',
  error: 'border-red-800 bg-red-950 text-red-200',
};

export default function Toasts() {
  const toasts = useStore((s) => s.toasts);
  return (
    <div className="fixed bottom-4 right-4 z-[100] flex flex-col gap-2 max-w-sm">
      {toasts.map((t) => (
        <div
          key={t.id}
          className={`rounded-lg border px-3 py-2 text-sm shadow-lg ${KIND_STYLES[t.kind] || KIND_STYLES.info}`}
        >
          {t.text}
        </div>
      ))}
    </div>
  );
}
