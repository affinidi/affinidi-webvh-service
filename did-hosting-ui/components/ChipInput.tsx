import { useEffect, useRef, useState } from "react";

import { colors, fonts, radii } from "../lib/theme";

/**
 * A list of values edited as chips (web only).
 *
 * Every control is a real `<button>`, so it is focusable and answers Enter
 * and Space: each chip's remove button is named for the value it removes, and
 * each suggestion is a button that adds itself. Enter in the text box adds
 * what was typed; Escape closes the suggestions.
 */
export function ChipInput({
  label,
  values,
  onChange,
  suggestions,
  placeholder,
  readOnly,
}: {
  /** What the list is ("Watchers") — names the text box and the group. */
  label: string;
  values: string[];
  onChange: (v: string[]) => void;
  suggestions?: string[];
  placeholder?: string;
  readOnly?: boolean;
}) {
  const [input, setInput] = useState("");
  const [showDropdown, setShowDropdown] = useState(false);
  const wrapperRef = useRef<HTMLDivElement>(null);

  const filtered = (suggestions ?? []).filter(
    (s) => !values.includes(s) && s.toLowerCase().includes(input.toLowerCase()),
  );

  const addValue = (v: string) => {
    const trimmed = v.trim();
    if (trimmed && !values.includes(trimmed)) {
      onChange([...values, trimmed]);
    }
    setInput("");
    setShowDropdown(false);
  };

  const removeValue = (v: string) => {
    onChange(values.filter((x) => x !== v));
  };

  // Close the suggestions on an outside click, or when focus leaves.
  useEffect(() => {
    const handler = (e: MouseEvent | FocusEvent) => {
      if (wrapperRef.current && !wrapperRef.current.contains(e.target as Node)) {
        setShowDropdown(false);
      }
    };
    document.addEventListener("mousedown", handler);
    document.addEventListener("focusin", handler);
    return () => {
      document.removeEventListener("mousedown", handler);
      document.removeEventListener("focusin", handler);
    };
  }, []);

  return (
    <div ref={wrapperRef} role="group" aria-label={label} style={{ position: "relative" }}>
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          gap: 6,
          alignItems: "center",
          minHeight: 36,
        }}
      >
        {values.map((v) => (
          <span
            key={v}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: 4,
              backgroundColor: colors.bgTertiary,
              border: `1px solid ${colors.border}`,
              borderRadius: radii.full,
              padding: "3px 10px",
              fontSize: 12,
              fontFamily: fonts.mono,
              color: colors.textPrimary,
            }}
          >
            <span
              style={{
                maxWidth: 280,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {v}
            </span>
            {!readOnly && (
              <button
                type="button"
                aria-label={`Remove ${v}`}
                onClick={() => removeValue(v)}
                style={{
                  background: "none",
                  border: "none",
                  color: colors.textSecondary,
                  cursor: "pointer",
                  fontSize: 14,
                  padding: "0 2px",
                  lineHeight: 1,
                }}
              >
                ×
              </button>
            )}
          </span>
        ))}
        {!readOnly && (
          <input
            type="text"
            aria-label={`Add to ${label}`}
            value={input}
            onChange={(e) => {
              setInput(e.target.value);
              setShowDropdown(true);
            }}
            onFocus={() => setShowDropdown(true)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault();
                addValue(input);
              } else if (e.key === "Escape") {
                setShowDropdown(false);
              }
            }}
            placeholder={values.length === 0 ? placeholder : ""}
            style={{
              flex: 1,
              minWidth: 120,
              background: "none",
              border: "none",
              color: colors.textPrimary,
              fontFamily: fonts.mono,
              fontSize: 12,
              padding: "4px 0",
            }}
          />
        )}
        {readOnly && values.length === 0 && (
          <span
            style={{
              color: colors.textTertiary,
              fontSize: 12,
              fontFamily: fonts.regular,
            }}
          >
            None
          </span>
        )}
      </div>
      {showDropdown && filtered.length > 0 && !readOnly && (
        <div
          aria-label={`Suggestions for ${label}`}
          role="group"
          style={{
            position: "absolute",
            top: "100%",
            left: 0,
            right: 0,
            zIndex: 10,
            backgroundColor: colors.bgSecondary,
            border: `1px solid ${colors.border}`,
            borderRadius: radii.sm,
            maxHeight: 160,
            overflowY: "auto",
            marginTop: 4,
          }}
        >
          {filtered.map((s) => (
            <button
              type="button"
              key={s}
              aria-label={`Add ${s}`}
              onClick={() => addValue(s)}
              onKeyDown={(e) => {
                if (e.key === "Escape") setShowDropdown(false);
              }}
              style={{
                display: "block",
                width: "100%",
                textAlign: "left",
                background: "none",
                border: "none",
                padding: "6px 10px",
                fontSize: 12,
                fontFamily: fonts.mono,
                color: colors.textPrimary,
                cursor: "pointer",
                borderBottom: `1px solid ${colors.border}`,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.backgroundColor = colors.bgTertiary;
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.backgroundColor = "transparent";
              }}
              onFocus={(e) => {
                e.currentTarget.style.backgroundColor = colors.bgTertiary;
              }}
              onBlur={(e) => {
                e.currentTarget.style.backgroundColor = "transparent";
              }}
            >
              {s}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
