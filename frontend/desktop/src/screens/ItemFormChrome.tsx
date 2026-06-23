import { useState } from "react";
import type { ReactNode, SyntheticEvent } from "react";
import { useT } from "@kunuk/shared-ui";
import { useCopyFeedback } from "../hooks/useCopyFeedback";
import type { CustomFieldDto } from "../tauri";

interface Props {
  heading: string;
  title: string;
  onTitleChange: (v: string) => void;
  customFields: CustomFieldDto[];
  onCustomFieldsChange: (v: CustomFieldDto[]) => void;
  favorite: boolean;
  onFavoriteChange: (v: boolean) => void;
  onSave: () => Promise<void>;
  onCancel: () => void;
  onDelete?: (() => Promise<void>) | undefined;
  children: ReactNode;
}

/** Involucro comune ai 4 form di voce (Login/Nota/Carta/Identità, C2): titolo, campi
 * personalizzati, preferito e azioni — solo i campi tipizzati del payload restano nel form
 * chiamante (passati come `children`, tra titolo e campi personalizzati). */
export function ItemFormChrome(props: Props) {
  const t = useT();
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const { copiedKey: copiedFieldIndex, copy, clear: clearCopyFeedback } = useCopyFeedback<number>();

  function handleSubmit(e: SyntheticEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setPending(true);
    props
      .onSave()
      .catch(() => {
        setError(t("auth.error.generic"));
      })
      .finally(() => {
        setPending(false);
      });
  }

  function handleDelete() {
    if (props.onDelete === undefined) return;
    if (!window.confirm(t("vault.confirmDelete"))) return;
    setError(null);
    setPending(true);
    props.onDelete().catch(() => {
      setError(t("auth.error.generic"));
      setPending(false);
    });
  }

  const fields = props.customFields;

  return (
    <form className="auth-form item-form" onSubmit={handleSubmit}>
      <h1 className="auth-form__title">{props.heading}</h1>
      <label className="auth-form__field">
        {t("item.common.title")}
        <input
          type="text"
          required
          value={props.title}
          onChange={(e) => {
            props.onTitleChange(e.target.value);
          }}
        />
      </label>
      {props.children}
      <fieldset className="item-form__fieldset">
        <legend>{t("item.common.customFields")}</legend>
        {fields.map((field, i) => (
          <div className="item-form__row" key={i}>
            <input
              type="text"
              placeholder={t("item.common.fieldLabel")}
              value={field.label}
              onChange={(e) => {
                props.onCustomFieldsChange(
                  fields.map((f, j) => (j === i ? { ...f, label: e.target.value } : f))
                );
              }}
            />
            <input
              type={field.hidden ? "password" : "text"}
              placeholder={t("item.common.fieldValue")}
              value={field.value}
              onChange={(e) => {
                props.onCustomFieldsChange(
                  fields.map((f, j) => (j === i ? { ...f, value: e.target.value } : f))
                );
              }}
            />
            <label className="item-form__checkbox">
              <input
                type="checkbox"
                checked={field.hidden}
                onChange={(e) => {
                  props.onCustomFieldsChange(
                    fields.map((f, j) => (j === i ? { ...f, hidden: e.target.checked } : f))
                  );
                }}
              />
              {t("item.common.fieldHidden")}
            </label>
            {field.hidden && (
              <button
                type="button"
                className="auth-form__link"
                onClick={() => {
                  copy(i, field.value);
                }}
              >
                {copiedFieldIndex === i ? t("item.common.copied") : t("item.common.copy")}
              </button>
            )}
            <button
              type="button"
              className="auth-form__link"
              aria-label={t("item.common.removeField")}
              onClick={() => {
                // Rimuovere un campo sposta gli indici di quelli successivi: azzerare il
                // feedback "Copiato" piuttosto che lasciarlo (sbagliato) su un campo diverso
                // da quello davvero copiato (scoperto in code review).
                clearCopyFeedback();
                props.onCustomFieldsChange(fields.filter((_, j) => j !== i));
              }}
            >
              ×
            </button>
          </div>
        ))}
        <button
          type="button"
          className="auth-form__link"
          onClick={() => {
            props.onCustomFieldsChange([...fields, { label: "", value: "", hidden: false }]);
          }}
        >
          {t("item.common.addCustomField")}
        </button>
      </fieldset>
      <label className="item-form__checkbox">
        <input
          type="checkbox"
          checked={props.favorite}
          onChange={(e) => {
            props.onFavoriteChange(e.target.checked);
          }}
        />
        {t("item.common.favorite")}
      </label>
      {error !== null && <p className="auth-form__error">{error}</p>}
      <div className="item-form__actions">
        <button type="submit" className="auth-form__primary" disabled={pending}>
          {t("vault.save")}
        </button>
        <button type="button" className="auth-form__link" onClick={props.onCancel}>
          {t("vault.cancel")}
        </button>
        {props.onDelete !== undefined && (
          <button
            type="button"
            className="auth-form__link"
            disabled={pending}
            onClick={handleDelete}
          >
            {t("vault.delete")}
          </button>
        )}
      </div>
    </form>
  );
}
