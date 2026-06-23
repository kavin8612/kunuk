import { useState } from "react";
import type { SyntheticEvent } from "react";
import {
  MAX_AUTO_LOCK_MINUTES,
  MAX_CLIPBOARD_CLEAR_SECONDS,
  MIN_AUTO_LOCK_MINUTES,
  MIN_CLIPBOARD_CLEAR_SECONDS,
  useT,
} from "@kunuk/shared-ui";
import { saveSettings, type SecuritySettingsDto } from "../tauri";

interface Props {
  settings: SecuritySettingsDto;
  onSaved: (settings: SecuritySettingsDto) => void;
  onCancel: () => void;
}

/** Limita `value` a `[min, max]` (un input vuoto dà `Number('') === 0`, non `NaN`): applicato
 * già negli `onChange`, non solo al salvataggio, perché ciò che il campo mostra deve sempre
 * coincidere con ciò che verrà salvato — altrimenti il valore può cambiare silenziosamente al
 * Save senza che l'utente se ne accorga (scoperto in code review). La validazione definitiva
 * resta lato Rust (`save_settings`), questa è solo UX. */
function clampInput(value: number, min: number, max: number): number {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, value));
}

/** Impostazioni di sicurezza (doc 17 §9): timeout di auto-lock e durata di pulizia della
 * clipboard, entrambi "configurabili". Posseduti da Rust (`src-tauri/src/settings.rs`), non
 * da `localStorage` — sono parametri di policy di sicurezza, non semplici preferenze UI
 * (scoperto in code review). */
export function SettingsScreen(props: Props) {
  const t = useT();
  const [autoLockMinutes, setAutoLockMinutes] = useState(props.settings.auto_lock_minutes);
  const [clipboardClearSeconds, setClipboardClearSeconds] = useState(
    props.settings.clipboard_clear_seconds
  );
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  function handleSubmit(e: SyntheticEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setPending(true);
    saveSettings({
      auto_lock_minutes: autoLockMinutes,
      clipboard_clear_seconds: clipboardClearSeconds,
    })
      .then((saved) => {
        props.onSaved(saved);
      })
      .catch(() => {
        setError(t("auth.error.generic"));
      })
      .finally(() => {
        setPending(false);
      });
  }

  return (
    <form className="auth-form" onSubmit={handleSubmit}>
      <h1 className="auth-form__title">{t("settings.title")}</h1>
      <label className="auth-form__field">
        {t("settings.autoLockMinutes")}
        <input
          type="number"
          min={MIN_AUTO_LOCK_MINUTES}
          max={MAX_AUTO_LOCK_MINUTES}
          value={autoLockMinutes}
          onChange={(e) => {
            setAutoLockMinutes(
              clampInput(Number(e.target.value), MIN_AUTO_LOCK_MINUTES, MAX_AUTO_LOCK_MINUTES)
            );
          }}
        />
      </label>
      <label className="auth-form__field">
        {t("settings.clipboardClearSeconds")}
        <input
          type="number"
          min={MIN_CLIPBOARD_CLEAR_SECONDS}
          max={MAX_CLIPBOARD_CLEAR_SECONDS}
          value={clipboardClearSeconds}
          onChange={(e) => {
            setClipboardClearSeconds(
              clampInput(
                Number(e.target.value),
                MIN_CLIPBOARD_CLEAR_SECONDS,
                MAX_CLIPBOARD_CLEAR_SECONDS
              )
            );
          }}
        />
      </label>
      {error !== null && <p className="auth-form__error">{error}</p>}
      <div className="item-form__actions">
        <button type="submit" className="auth-form__primary" disabled={pending}>
          {t("vault.save")}
        </button>
        <button type="button" className="auth-form__link" onClick={props.onCancel}>
          {t("vault.cancel")}
        </button>
      </div>
    </form>
  );
}
