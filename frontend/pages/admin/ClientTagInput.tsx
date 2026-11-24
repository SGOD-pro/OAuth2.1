import React, { useId, useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';

interface ClientTagInputProps {
  id: string;
  tags: string[];
  placeholder: string;
  validate: (val: string) => string | null;
  onAdd: (val: string) => void;
  onRemove: (val: string) => void;
  describedByHintId?: string;
}

export const ClientTagInput: React.FC<ClientTagInputProps> = ({
  id,
  tags,
  placeholder,
  validate,
  onAdd,
  onRemove,
  describedByHintId,
}) => {
  const [input, setInput] = useState('');
  const [err, setErr] = useState<string | null>(null);
  const errorId = useId();

  const runValidation = (raw: string): string | null => {
    const val = raw.trim();
    if (!val) return null;
    const msg = validate(val);
    if (msg) return msg;
    if (tags.includes(val)) return 'Already added';
    return null;
  };

  const add = () => {
    const val = input.trim();
    if (!val) return;
    const msg = runValidation(val);
    if (msg) {
      setErr(msg);
      return;
    }
    onAdd(val);
    setInput('');
    setErr(null);
  };

  const handleBlur = () => {
    if (!input.trim()) {
      setErr(null);
      return;
    }
    setErr(runValidation(input));
  };

  const handleChange = (next: string) => {
    setInput(next);
    if (err) {
      const trimmed = next.trim();
      if (!trimmed || !runValidation(trimmed)) {
        setErr(null);
      }
    }
  };

  const describedBy = [describedByHintId, err ? errorId : null].filter(Boolean).join(' ') || undefined;

  return (
    <div>
      <div className="flex gap-2">
        <Input
          id={id}
          type="url"
          placeholder={placeholder}
          value={input}
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          aria-invalid={err ? 'true' : 'false'}
          aria-describedby={describedBy}
          onChange={(e) => handleChange(e.target.value)}
          onBlur={handleBlur}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && !e.nativeEvent.isComposing) {
              e.preventDefault();
              add();
            }
          }}
          className="h-9"
        />
        <Button type="button" variant="outline" size="sm" onClick={add} className="h-9 px-3 shrink-0">
          Add
        </Button>
      </div>
      {err && (
        <p id={errorId} role="alert" className="mt-1.5 font-sans text-xs text-destructive">
          {err}
        </p>
      )}
      {tags.length > 0 && (
        <div className="mt-2 flex flex-wrap gap-1.5">
          {tags.map((t) => (
            <span
              key={t}
              className="flex items-center gap-1.5 rounded-md bg-secondary border border-border px-2.5 py-0.5 font-mono text-xs text-foreground"
            >
              {t}
              <button
                type="button"
                className="text-muted-foreground hover:text-foreground ml-1"
                onClick={() => onRemove(t)}
                aria-label={`Remove ${t}`}
              >
                ×
              </button>
            </span>
          ))}
        </div>
      )}
    </div>
  );
};
