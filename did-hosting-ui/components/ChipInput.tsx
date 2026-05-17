import { useEffect, useState, useRef } from "react";
import { colors, fonts, radii } from "../lib/theme";

export function ChipInput({
  values,
  onChange,
  suggestions,
  placeholder,
  readOnly,
}: {
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
    (s) =>
      !values.includes(s) &&
      s.toLowerCase().includes(input.toLowerCase()),
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

  // Close dropdown on outside click
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (wrapperRef.current && !wrapperRef.current.contains(e.target as Node)) {
        setShowDropdown(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  return (
    <div ref={wrapperRef} style={{ position: "relative" }}>
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
                onClick={() => removeValue(v)}
                style={{
                  background: "none",
                  border: "none",
                  color: colors.textTertiary,
                  cursor: "pointer",
                  fontSize: 14,
                  padding: 0,
                  lineHeight: 1,
                }}
              >
                x
              </button>
            )}
          </span>
        ))}
        {!readOnly && (
          <input
            type="text"
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
              }
            }}
            placeholder={values.length === 0 ? placeholder : ""}
            style={{
              flex: 1,
              minWidth: 120,
              background: "none",
              border: "none",
              outline: "none",
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
            <div
              key={s}
              onClick={() => addValue(s)}
              style={{
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
                (e.target as HTMLDivElement).style.backgroundColor =
                  colors.bgTertiary;
              }}
              onMouseLeave={(e) => {
                (e.target as HTMLDivElement).style.backgroundColor =
                  "transparent";
              }}
            >
              {s}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
