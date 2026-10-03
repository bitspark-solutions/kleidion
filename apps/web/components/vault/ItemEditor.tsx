"use client";

// Create/edit dialog for an ItemPlain. Field templates per itemType
// (1 Login, 2 SecureNote, 3 Card, 4 Identity). Validation: title required.
// Encryption happens in VaultShell (it owns the vault key); this component
// only collects and validates the plaintext.

import { useState, type FormEvent } from "react";
import {
  ITEM_TYPES,
  ITEM_TYPE_LABELS,
  type ItemField,
  type ItemFieldType,
  type ItemPlain,
} from "@/lib/types";

export interface ItemEditorProps {
  /** Existing plaintext when editing; null when creating. */
  initial: ItemPlain | null;
  /** Locked when editing (contract has no itemType mutation via PUT semantics we rely on). */
  initialItemType: number;
  itemTypeLocked: boolean;
  saving: boolean;
  saveError: string | null;
  onSave: (itemType: number, plain: ItemPlain) => Promise<void>;
  onCancel: () => void;
}

interface TemplateField {
  label: string;
  type: ItemFieldType;
}

const FIELD_TEMPLATES: Record<number, TemplateField[]> = {
  [ITEM_TYPES.Login]: [
    { label: "Username", type: "text" },
    { label: "Password", type: "password" },
    { label: "Website", type: "url" },
    { label: "TOTP", type: "totp" },
  ],
  [ITEM_TYPES.SecureNote]: [],
  [ITEM_TYPES.Card]: [
    { label: "Cardholder", type: "text" },
    { label: "Number", type: "password" },
    { label: "Expiry", type: "text" },
    { label: "CVC", type: "password" },
  ],
  [ITEM_TYPES.Identity]: [
    { label: "Full name", type: "text" },
    { label: "Email", type: "text" },
    { label: "Phone", type: "text" },
    { label: "Address", type: "text" },
  ],
};

function fieldsFromTemplate(itemType: number): ItemField[] {
  return (FIELD_TEMPLATES[itemType] ?? []).map((t) => ({
    label: t.label,
    value: "",
    type: t.type,
  }));
}

const TYPE_OPTIONS: number[] = [
  ITEM_TYPES.Login,
  ITEM_TYPES.SecureNote,
  ITEM_TYPES.Card,
  ITEM_TYPES.Identity,
];

const inputCls =
  "w-full rounded-md border border-border bg-bg px-2.5 py-1.5 text-sm text-fg placeholder:text-fg-muted focus:border-accent focus:outline-none";

export default function ItemEditor({
  initial,
  initialItemType,
  itemTypeLocked,
  saving,
  saveError,
  onSave,
  onCancel,
}: ItemEditorProps) {
  const [itemType, setItemType] = useState<number>(initialItemType);
  const [title, setTitle] = useState(initial?.title ?? "");
  const [notes, setNotes] = useState(initial?.notes ?? "");
  const [tags, setTags] = useState((initial?.tags ?? []).join(", "));
  const [fields, setFields] = useState<ItemField[]>(
    initial?.fields ?? fieldsFromTemplate(initialItemType),
  );
  const [titleError, setTitleError] = useState<string | null>(null);

  function changeType(next: number) {
    setItemType(next);
    // Swap to the template for the new type, carrying over nothing —
    // templates differ per type (Login vs Card fields would be nonsense mixed).
    setFields(fieldsFromTemplate(next));
  }

  function updateField(i: number, patch: Partial<ItemField>) {
    setFields((prev) => prev.map((f, idx) => (idx === i ? { ...f, ...patch } : f)));
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!title.trim()) {
      setTitleError("Title is required.");
      return;
    }
    setTitleError(null);
    const plain: ItemPlain = {
      title: title.trim(),
      ...(notes.trim() ? { notes: notes.trim() } : {}),
      ...(() => {
        const parsed = tags
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean);
        return parsed.length > 0 ? { tags: parsed } : {};
      })(),
      // Drop empty fields so we don't store noise; keep order.
      ...(() => {
        const kept = fields.filter((f) => f.label.trim() && f.value !== "");
        return kept.length > 0 ? { fields: kept } : {};
      })(),
    };
    await onSave(itemType, plain);
  }

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={initial ? "Edit item" : "New item"}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4"
      onClick={onCancel}
    >
      <form
        onSubmit={submit}
        onClick={(e) => e.stopPropagation()}
        className="max-h-full w-full max-w-lg overflow-y-auto rounded-xl border border-border bg-surface p-5 shadow-2xl"
      >
        <h2 className="text-base font-semibold text-fg">
          {initial ? "Edit item" : "New item"}
        </h2>

        <div className="mt-4 space-y-4">
          <label className="block">
            <span className="mb-1 block text-xs text-fg-muted">Type</span>
            <select
              value={itemType}
              onChange={(e) => changeType(Number(e.target.value))}
              disabled={itemTypeLocked}
              className={inputCls}
            >
              {TYPE_OPTIONS.map((t) => (
                <option key={t} value={t}>
                  {ITEM_TYPE_LABELS[t]}
                </option>
              ))}
            </select>
          </label>

          <label className="block">
            <span className="mb-1 block text-xs text-fg-muted">
              Title <span className="text-danger">*</span>
            </span>
            <input
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. GitHub"
              autoFocus
              aria-invalid={titleError !== null}
              className={`${inputCls} ${titleError ? "border-danger" : ""}`}
            />
            {titleError && (
              <span role="alert" className="mt-1 block text-xs text-danger">
                {titleError}
              </span>
            )}
          </label>

          {fields.length > 0 && (
            <fieldset>
              <legend className="mb-1 text-xs text-fg-muted">Fields</legend>
              <div className="space-y-2">
                {fields.map((f, i) => (
                  <div key={`${f.label}-${i}`} className="flex items-center gap-2">
                    <span className="w-24 shrink-0 truncate text-xs text-fg-muted">
                      {f.label}
                    </span>
                    <input
                      type={f.type === "password" ? "password" : f.type === "url" ? "url" : "text"}
                      value={f.value}
                      onChange={(e) => updateField(i, { value: e.target.value })}
                      placeholder={f.type === "totp" ? "otpauth://… or secret" : f.label}
                      className={inputCls}
                      autoComplete="off"
                    />
                  </div>
                ))}
              </div>
            </fieldset>
          )}

          <label className="block">
            <span className="mb-1 block text-xs text-fg-muted">Notes</span>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              rows={3}
              className={inputCls}
            />
          </label>

          <label className="block">
            <span className="mb-1 block text-xs text-fg-muted">
              Tags <span className="opacity-60">(comma-separated)</span>
            </span>
            <input
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="work, dev"
              className={inputCls}
            />
          </label>
        </div>

        {saveError && (
          <p role="alert" className="mt-3 text-xs text-danger">
            {saveError}
          </p>
        )}

        <div className="mt-5 flex justify-end gap-2">
          <button
            type="button"
            onClick={onCancel}
            className="rounded-md border border-border px-3 py-1.5 text-sm text-fg-muted hover:bg-surface-hover hover:text-fg"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={saving}
            className="rounded-md bg-accent px-4 py-1.5 text-sm font-medium text-accent-fg hover:opacity-90 disabled:opacity-50"
          >
            {saving ? "Saving…" : initial ? "Save changes" : "Create item"}
          </button>
        </div>
      </form>
    </div>
  );
}
