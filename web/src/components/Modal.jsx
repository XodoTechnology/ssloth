import React, { useEffect } from 'react';
import { X } from 'lucide-react';

export default function Modal({ title, onClose, children, wide }) {
  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && onClose?.();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
      onMouseDown={(e) => e.target === e.currentTarget && onClose?.()}
    >
      <div className={`card w-full ${wide ? 'max-w-2xl' : 'max-w-md'} shadow-2xl`}>
        <div className="flex items-center justify-between border-b border-ink-700 px-4 py-3">
          <h2 className="text-sm font-semibold text-zinc-100">{title}</h2>
          <button className="text-zinc-500 hover:text-zinc-200" onClick={onClose}>
            <X size={16} />
          </button>
        </div>
        <div className="p-4 max-h-[75vh] overflow-y-auto">{children}</div>
      </div>
    </div>
  );
}
