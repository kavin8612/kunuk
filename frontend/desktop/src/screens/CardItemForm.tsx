import { useState } from "react";
import { useT } from "@kunuk/shared-ui";
import { ItemFormChrome } from "./ItemFormChrome";
import { useCopyFeedback } from "../hooks/useCopyFeedback";
import type { CustomFieldDto, ItemContentDto, ItemDataDto } from "../tauri";

export type CardContent = ItemContentDto & { data: Extract<ItemDataDto, { type: "card" }> };

interface Props {
  mode: "create" | "edit";
  initialContent: CardContent;
  onSubmit: (content: CardContent) => Promise<void>;
  onDelete?: () => Promise<void>;
  onCancel: () => void;
}

/** Form di creazione/modifica di una carta di pagamento (C2, task #15). `exp_month`/
 * `exp_year` sono numerici nel core (`u8`/`u16`, doc 16 §5): l'input `number` con min/max basta
 * per questo MVP, senza validazione aggiuntiva lato client. */
export function CardItemForm(props: Props) {
  const t = useT();
  const [title, setTitle] = useState(props.initialContent.title);
  const [favorite, setFavorite] = useState(props.initialContent.favorite);
  const [customFields, setCustomFields] = useState<CustomFieldDto[]>(
    props.initialContent.custom_fields
  );
  const [cardholderName, setCardholderName] = useState(props.initialContent.data.cardholder_name);
  const [number, setNumber] = useState(props.initialContent.data.number);
  const [expMonth, setExpMonth] = useState(props.initialContent.data.exp_month);
  const [expYear, setExpYear] = useState(props.initialContent.data.exp_year);
  const [securityCode, setSecurityCode] = useState(props.initialContent.data.security_code);
  const [showCode, setShowCode] = useState(false);
  const { copiedKey, copy } = useCopyFeedback<true>();

  function save() {
    return props.onSubmit({
      title,
      folder: props.initialContent.folder,
      favorite,
      custom_fields: customFields.filter((f) => f.label.trim() !== ""),
      data: {
        type: "card",
        cardholder_name: cardholderName,
        number,
        exp_month: expMonth,
        exp_year: expYear,
        security_code: securityCode,
      },
    });
  }

  return (
    <ItemFormChrome
      heading={props.mode === "create" ? t("item.card.newTitle") : t("item.card.editTitle")}
      title={title}
      onTitleChange={setTitle}
      favorite={favorite}
      onFavoriteChange={setFavorite}
      customFields={customFields}
      onCustomFieldsChange={setCustomFields}
      onSave={save}
      onCancel={props.onCancel}
      onDelete={props.onDelete}
    >
      <label className="auth-form__field">
        {t("item.card.cardholderName")}
        <input
          type="text"
          autoComplete="cc-name"
          value={cardholderName}
          onChange={(e) => {
            setCardholderName(e.target.value);
          }}
        />
      </label>
      <label className="auth-form__field">
        {t("item.card.number")}
        <input
          type="text"
          inputMode="numeric"
          autoComplete="cc-number"
          value={number}
          onChange={(e) => {
            setNumber(e.target.value);
          }}
        />
      </label>
      <div className="item-form__pair">
        <label className="auth-form__field">
          {t("item.card.expMonth")}
          <input
            type="number"
            min={1}
            max={12}
            autoComplete="cc-exp-month"
            value={expMonth}
            onChange={(e) => {
              setExpMonth(Number(e.target.value));
            }}
          />
        </label>
        <label className="auth-form__field">
          {t("item.card.expYear")}
          <input
            type="number"
            min={2000}
            max={2200}
            autoComplete="cc-exp-year"
            value={expYear}
            onChange={(e) => {
              setExpYear(Number(e.target.value));
            }}
          />
        </label>
      </div>
      <div className="auth-form__field">
        <label htmlFor="card-form-cvv">{t("item.card.securityCode")}</label>
        <div className="item-form__password-row">
          <input
            id="card-form-cvv"
            type={showCode ? "text" : "password"}
            inputMode="numeric"
            autoComplete="cc-csc"
            value={securityCode}
            onChange={(e) => {
              setSecurityCode(e.target.value);
            }}
          />
          <button
            type="button"
            className="auth-form__link"
            onClick={() => {
              setShowCode(!showCode);
            }}
          >
            {showCode ? t("item.common.hide") : t("item.common.reveal")}
          </button>
          <button
            type="button"
            className="auth-form__link"
            onClick={() => {
              copy(true, securityCode);
            }}
          >
            {copiedKey === true ? t("item.common.copied") : t("item.common.copy")}
          </button>
        </div>
      </div>
    </ItemFormChrome>
  );
}
