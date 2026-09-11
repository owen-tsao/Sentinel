"use client";

import { X } from "lucide-react";
import { useEffect, useId, useMemo, useRef, useState, type KeyboardEvent } from "react";

import { cn } from "@/lib/utils";

/**
 * Chip list + typeahead for exact targets (workspace paths or fixture issue IDs).
 *
 * Suggestions come from the server's read-only listing and only save typing;
 * anything typed is accepted as a chip too, and the server validates every
 * target on save. Typed text is committed on Enter and on blur so nothing is
 * silently dropped when the user clicks straight to Confirm.
 */
export function TargetPicker({
  id,
  values,
  onChange,
  suggestions,
  placeholder,
  disabled = false,
  emptyHint,
  normalize = (value) => value,
}: {
  id: string;
  values: string[];
  onChange: (next: string[]) => void;
  suggestions: string[];
  placeholder: string;
  disabled?: boolean;
  /** Shown under the list when there is nothing to suggest yet. */
  emptyHint?: string;
  /** Canonicalise typed text before it becomes a chip (e.g. prefix the workspace root). */
  normalize?: (value: string) => string;
}) {
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [highlight, setHighlight] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const rootRef = useRef<HTMLDivElement>(null);
  const listId = useId();

  const matches = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const remaining = suggestions.filter((item) => !values.includes(item));
    const filtered = needle
      ? remaining.filter((item) => item.toLowerCase().includes(needle))
      : remaining;
    return filtered.slice(0, 8);
  }, [query, suggestions, values]);
  // The stored index can outlive a shrinking list; clamp instead of syncing state.
  const active = Math.min(highlight, Math.max(matches.length - 1, 0));

  useEffect(() => {
    if (!open) return;
    function onPointerDown(event: PointerEvent) {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    }
    document.addEventListener("pointerdown", onPointerDown);
    return () => document.removeEventListener("pointerdown", onPointerDown);
  }, [open]);

  function add(raw: string) {
    const items = raw
      .split(/[\n,]/)
      .map((item) => normalize(item.trim()))
      .filter(Boolean)
      .filter((item, index, all) => !values.includes(item) && all.indexOf(item) === index);
    if (items.length) onChange([...values, ...items]);
    setQuery("");
  }

  function remove(target: string) {
    onChange(values.filter((item) => item !== target));
    inputRef.current?.focus();
  }

  function onKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setOpen(true);
      setHighlight(Math.min(active + 1, Math.max(matches.length - 1, 0)));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setHighlight(Math.max(active - 1, 0));
    } else if (event.key === "Enter") {
      event.preventDefault();
      if (open && matches[active]) add(matches[active]);
      else if (query.trim()) add(query);
      setOpen(false);
    } else if (event.key === "Escape") {
      setOpen(false);
    } else if (event.key === "Backspace" && !query && values.length) {
      onChange(values.slice(0, -1));
    }
  }

  const showList = open && !disabled && (matches.length > 0 || Boolean(emptyHint));
  const activeId = showList && matches[active] ? `${listId}-${active}` : undefined;

  return (
    <div ref={rootRef} className="relative">
      <div
        className={cn(
          "flex min-h-9 w-full flex-wrap items-center gap-1.5 rounded-[var(--radius-control)] border-[1.5px] border-[var(--outline)] bg-white px-2 py-1.5 transition-[box-shadow] focus-within:shadow-[0_0_0_3px_var(--main-soft)]",
          disabled && "cursor-not-allowed bg-[var(--canvas)] opacity-55",
        )}
        onClick={() => {
          inputRef.current?.focus();
          if (!disabled) setOpen(true);
        }}
      >
        {values.map((target) => (
          <span
            key={target}
            className="inline-flex max-w-full items-center gap-1 rounded-[5px] border border-[var(--outline)] bg-white pl-1.5 font-mono text-[11px] font-medium leading-[20px]"
          >
            <span className="truncate">{target}</span>
            <button
              type="button"
              aria-label={`Remove ${target}`}
              disabled={disabled}
              className="grid size-5 place-items-center rounded-r-[4px] text-[var(--subtext)] outline-none hover:bg-[var(--hover)] hover:text-[var(--ink)] focus-visible:ring-2 focus-visible:ring-black focus-visible:ring-inset disabled:pointer-events-none"
              onClick={(event) => {
                event.stopPropagation();
                remove(target);
              }}
            >
              <X aria-hidden="true" size={11} strokeWidth={2} />
            </button>
          </span>
        ))}
        <input
          ref={inputRef}
          id={id}
          role="combobox"
          aria-expanded={showList}
          aria-controls={listId}
          aria-autocomplete="list"
          aria-activedescendant={activeId}
          autoComplete="off"
          spellCheck={false}
          disabled={disabled}
          value={query}
          placeholder={values.length ? "Add another" : placeholder}
          className="min-w-[160px] flex-1 bg-transparent px-1 font-mono text-[12px] outline-none placeholder:font-sans placeholder:text-[13px] placeholder:text-[var(--faint)]"
          onChange={(event) => {
            setQuery(event.target.value);
            setHighlight(0);
            setOpen(true);
          }}
          onFocus={() => setOpen(true)}
          onBlur={() => {
            if (query.trim()) add(query);
          }}
          onKeyDown={onKeyDown}
          onPaste={(event) => {
            const text = event.clipboardData.getData("text");
            if (/[\n,]/.test(text)) {
              event.preventDefault();
              add(text);
            }
          }}
        />
      </div>

      <ul
        id={listId}
        role="listbox"
        aria-label="Suggested targets"
        hidden={!showList}
        className="absolute left-0 right-0 top-full z-20 mt-1.5 max-h-[248px] overflow-auto rounded-[var(--radius-control)] border-[1.5px] border-[var(--outline)] bg-white p-1 shadow-[3px_3px_0_0_#000]"
      >
        {matches.map((item, index) => (
          <li
            key={item}
            id={`${listId}-${index}`}
            role="option"
            aria-selected={index === active}
            className={cn(
              "cursor-pointer truncate rounded-[5px] px-2.5 py-1.5 font-mono text-[12px]",
              index === active && "bg-[var(--hover)]",
            )}
            onMouseDown={(event) => {
              // Keep focus on the input; the click must not fire blur first.
              event.preventDefault();
              add(item);
              setOpen(false);
            }}
            onMouseEnter={() => setHighlight(index)}
          >
            {item}
          </li>
        ))}
        {matches.length === 0 && emptyHint ? (
          <li className="px-2.5 py-1.5 text-[12px] text-[var(--subtext)]">{emptyHint}</li>
        ) : null}
      </ul>
    </div>
  );
}
