import { useEffect, useState } from "react";
import { estimatePasswordEntropyBits, passphraseEntropyBits, useT } from "@kunuk/shared-ui";
import {
  generatePassphrase,
  generatePassword,
  type PassphraseLang,
  type PasswordPolicyDto,
} from "../tauri";
import { StrengthMeter } from "../components/StrengthMeter";
import { useCopyFeedback } from "../hooks/useCopyFeedback";

type Tab = "password" | "passphrase";

// Dimensione delle due wordlist diceware del core (`crypto-core/src/generator/`,
// `wordlist_en.txt`/`wordlist_it.txt`): l'entropia di una passphrase è nota a priori
// (estrazione uniforme), non va stimata dal testo come per una password digitata.
const WORDLIST_SIZE: Record<PassphraseLang, number> = { en: 7776, it: 8192 };

interface Props {
  /** Presente solo quando il generatore è aperto per riempire un campo password
   * (es. da `LoginItemForm`): mostra il bottone "Usa questa password". */
  onUse?: (value: string) => void;
  onClose: () => void;
}

/** Generatore password/passphrase (C3, doc 17 §3). Nessuna sessione: funziona anche a
 * vault bloccato (il core lo consente, doc 20 §9), qui è comunque raggiungibile solo
 * da dentro il vault sbloccato. */
export function GeneratorScreen(props: Props) {
  const t = useT();
  const [tab, setTab] = useState<Tab>("password");

  const [length, setLength] = useState(20);
  const [uppercase, setUppercase] = useState(true);
  const [lowercase, setLowercase] = useState(true);
  const [numbers, setNumbers] = useState(true);
  const [symbols, setSymbols] = useState(true);
  const [excludeAmbiguous, setExcludeAmbiguous] = useState(false);

  const [lang, setLang] = useState<PassphraseLang>("it");
  const [words, setWords] = useState(5);
  const [separator, setSeparator] = useState("-");

  const [value, setValue] = useState("");
  const { copiedKey, copy } = useCopyFeedback<true>();
  const [error, setError] = useState(false);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    const policy: PasswordPolicyDto = {
      length,
      uppercase,
      lowercase,
      numbers,
      symbols,
      exclude_ambiguous: excludeAmbiguous,
    };
    const request =
      tab === "password" ? generatePassword(policy) : generatePassphrase(lang, words, separator);
    request
      .then((v) => {
        setValue(v);
        setError(false);
      })
      .catch(() => {
        setError(true);
      });
  }, [
    tab,
    length,
    uppercase,
    lowercase,
    numbers,
    symbols,
    excludeAmbiguous,
    lang,
    words,
    separator,
    tick,
  ]);

  const bits =
    tab === "password"
      ? estimatePasswordEntropyBits(value)
      : passphraseEntropyBits(words, WORDLIST_SIZE[lang]);

  return (
    <div className="generator">
      <h1 className="auth-form__title">{t("generator.title")}</h1>
      <div className="generator__tabs">
        <button
          type="button"
          className={
            tab === "password" ? "generator__tab generator__tab--active" : "generator__tab"
          }
          onClick={() => {
            setTab("password");
          }}
        >
          {t("generator.tabPassword")}
        </button>
        <button
          type="button"
          className={
            tab === "passphrase" ? "generator__tab generator__tab--active" : "generator__tab"
          }
          onClick={() => {
            setTab("passphrase");
          }}
        >
          {t("generator.tabPassphrase")}
        </button>
      </div>

      <p className="generator__value">{value}</p>
      {error ? (
        <p className="auth-form__error">{t("auth.error.generic")}</p>
      ) : (
        <StrengthMeter bits={bits} />
      )}
      <div className="item-form__actions">
        <button
          type="button"
          className="auth-form__link"
          onClick={() => {
            setTick(tick + 1);
          }}
        >
          {t("generator.regenerate")}
        </button>
        <button
          type="button"
          className="auth-form__link"
          onClick={() => {
            copy(true, value);
          }}
        >
          {copiedKey === true ? t("generator.copied") : t("generator.copy")}
        </button>
      </div>

      {tab === "password" ? (
        <div className="generator__settings">
          <label className="auth-form__field">
            {t("generator.length")}
            <input
              type="number"
              min={4}
              max={128}
              value={length}
              onChange={(e) => {
                setLength(Number(e.target.value));
              }}
            />
          </label>
          <label className="item-form__checkbox">
            <input
              type="checkbox"
              checked={uppercase}
              onChange={(e) => {
                setUppercase(e.target.checked);
              }}
            />
            {t("generator.uppercase")}
          </label>
          <label className="item-form__checkbox">
            <input
              type="checkbox"
              checked={lowercase}
              onChange={(e) => {
                setLowercase(e.target.checked);
              }}
            />
            {t("generator.lowercase")}
          </label>
          <label className="item-form__checkbox">
            <input
              type="checkbox"
              checked={numbers}
              onChange={(e) => {
                setNumbers(e.target.checked);
              }}
            />
            {t("generator.numbers")}
          </label>
          <label className="item-form__checkbox">
            <input
              type="checkbox"
              checked={symbols}
              onChange={(e) => {
                setSymbols(e.target.checked);
              }}
            />
            {t("generator.symbols")}
          </label>
          <label className="item-form__checkbox">
            <input
              type="checkbox"
              checked={excludeAmbiguous}
              onChange={(e) => {
                setExcludeAmbiguous(e.target.checked);
              }}
            />
            {t("generator.excludeAmbiguous")}
          </label>
        </div>
      ) : (
        <div className="generator__settings">
          <label className="auth-form__field">
            {t("generator.language")}
            <select
              value={lang}
              onChange={(e) => {
                setLang(e.target.value as PassphraseLang);
              }}
            >
              <option value="it">{t("generator.languageIt")}</option>
              <option value="en">{t("generator.languageEn")}</option>
            </select>
          </label>
          <label className="auth-form__field">
            {t("generator.words")}
            <input
              type="number"
              min={3}
              max={12}
              value={words}
              onChange={(e) => {
                setWords(Number(e.target.value));
              }}
            />
          </label>
          <label className="auth-form__field">
            {t("generator.separator")}
            <input
              type="text"
              maxLength={3}
              value={separator}
              onChange={(e) => {
                setSeparator(e.target.value);
              }}
            />
          </label>
        </div>
      )}

      <div className="item-form__actions">
        {props.onUse !== undefined && (
          <button
            type="button"
            className="auth-form__primary"
            disabled={value === ""}
            onClick={() => {
              props.onUse?.(value);
            }}
          >
            {t("generator.usePassword")}
          </button>
        )}
        <button type="button" className="auth-form__link" onClick={props.onClose}>
          {t("generator.close")}
        </button>
      </div>
    </div>
  );
}
