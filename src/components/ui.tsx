import { X } from "lucide-react";
import type { ReactNode } from "react";

import { useSlidingPill } from "../lib/pill";

export function Switch({
  checked,
  onChange,
  disabled,
}: {
  checked: boolean;
  onChange: (value: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      className="switch"
      data-on={checked}
      disabled={disabled}
      aria-pressed={checked}
      onClick={() => onChange(!checked)}
    />
  );
}

export function ToggleRow({
  label,
  desc,
  checked,
  onChange,
  disabled,
}: {
  label: string;
  desc?: string;
  checked: boolean;
  onChange: (value: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <div className="toggle-row">
      <div className="grow">
        <div className="toggle-label">{label}</div>
        {desc && <div className="toggle-desc">{desc}</div>}
      </div>
      <Switch checked={checked} onChange={onChange} disabled={disabled} />
    </div>
  );
}

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <div className="field">
      <label>{label}</label>
      {children}
      {hint && <div className="hint">{hint}</div>}
    </div>
  );
}

export function Segmented<T extends string>({
  value,
  options,
  onChange,
  onHover,
}: {
  value: T;
  options: { value: T; label: string }[];
  onChange: (value: T) => void;
  /** The option under the cursor, or null once it leaves the track. Lets the
   *  caller explain the option being looked at, not just the chosen one. */
  onHover?: (value: T | null) => void;
}) {
  const { hostRef, pill, placed } = useSlidingPill<HTMLDivElement>("button.on", value);

  return (
    <div className="segmented" ref={hostRef}>
      {/* The accent fill lives out here rather than on the chosen button, so a
       * pick slides one element across the track instead of two buttons
       * swapping colours in place. */}
      {pill && (
        <span
          aria-hidden="true"
          className={`seg-pill${placed ? " sliding" : ""}`}
          style={{
            transform: `translate3d(${pill.x}px, ${pill.y}px, 0)`,
            width: pill.w,
            height: pill.h,
          }}
        />
      )}
      {options.map((option) => (
        <button
          key={option.value}
          type="button"
          className={option.value === value ? "on" : ""}
          onClick={() => onChange(option.value)}
          onMouseEnter={() => onHover?.(option.value)}
          onMouseLeave={() => onHover?.(null)}
          onFocus={() => onHover?.(option.value)}
          onBlur={() => onHover?.(null)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

export function Modal({
  open,
  title,
  onClose,
  children,
  footer,
  wide,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  if (!open) return null;
  return (
    <div
      className="modal-backdrop"
      onMouseDown={(e) => {
        // Only a click that starts *and* ends on the backdrop dismisses, so a
        // text selection dragged out of the dialog does not close it.
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className={wide ? "modal wide" : "modal"}>
        <div className="modal-head">
          <div className="modal-title">{title}</div>
          <button type="button" className="btn ghost icon" onClick={onClose}>
            <X size={16} />
          </button>
        </div>
        <div className="modal-body">{children}</div>
        {footer && <div className="modal-foot">{footer}</div>}
      </div>
    </div>
  );
}

export function Empty({
  icon,
  title,
  text,
  action,
}: {
  icon: ReactNode;
  title: string;
  text: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      {icon}
      <h3>{title}</h3>
      <p>{text}</p>
      {action && <div style={{ marginTop: 16 }}>{action}</div>}
    </div>
  );
}

/** Editable list of free-form strings (domains, CIDRs), one per line. */
export function StringList({
  label,
  hint,
  placeholder,
  value,
  onChange,
}: {
  label: string;
  hint?: string;
  placeholder?: string;
  value: string[];
  onChange: (value: string[]) => void;
}) {
  return (
    <Field label={label} hint={hint}>
      <textarea
        className="textarea"
        placeholder={placeholder}
        defaultValue={value.join("\n")}
        // Commit on blur rather than per-keystroke: every change restarts the
        // core, and doing that mid-typing would be unusable.
        onBlur={(e) =>
          onChange(
            e.target.value
              .split("\n")
              .map((line) => line.trim())
              .filter(Boolean),
          )
        }
      />
    </Field>
  );
}
