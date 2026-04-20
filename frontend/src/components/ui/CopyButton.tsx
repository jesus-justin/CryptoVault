import { useState } from 'react';
import { motion } from 'framer-motion';

interface CopyButtonProps {
  value: string;
  label?: string;
}

export function CopyButton({ value, label = 'Copy' }: CopyButtonProps) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(value);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1200);
  };

  return (
    <motion.button
      type="button"
      onClick={handleCopy}
      whileTap={{ scale: 0.96 }}
      className="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 transition hover:border-slate-900 hover:text-slate-900"
    >
      {copied ? 'Copied' : label}
    </motion.button>
  );
}
