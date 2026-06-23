import { useState } from "react";
import { estimatePasswordEntropyBits, useT } from "@kunuk/shared-ui";
import { ItemFormChrome } from "./ItemFormChrome";
import { GeneratorScreen } from "./GeneratorScreen";
import { StrengthMeter } from "../components/StrengthMeter";
import { useCopyFeedback } from "../hooks/useCopyFeedback";
import type { CustomFieldDto, ItemContentDto, ItemDataDto } from "../tauri";

export type LoginContent = ItemContentDto & { data: Extract<ItemDataDto, { type: "login" }> };

interface Props {
  mode: "create" | "edit";
  initialContent: LoginContent;
  onSubmit: (content: LoginContent) => Promise<void>;
  onDelete?: () => Promise<void>;
  onCancel: () => void;
}

/** Form di creazione/modifica di una voce Login: campi tipizzati qui, titolo/cartella/
 * preferito/campi personalizzati nell'involucro comune (`ItemFormChrome`). */
export function LoginItemForm(props: Props) {
  const t = useT();
  const [title, setTitle] = useState(props.initialContent.title);
  const [favorite, setFavorite] = useState(props.initialContent.favorite);
  const [customFields, setCustomFields] = useState<CustomFieldDto[]>(
    props.initialContent.custom_fields
  );
  const [username, setUsername] = useState(props.initialContent.data.username);
  const [password, setPassword] = useState(props.initialContent.data.password);
  const [showPassword, setShowPassword] = useState(false);
  const { copiedKey, copy } = useCopyFeedback<true>();
  const [notes, setNotes] = useState(props.initialContent.data.notes);
  const [uris, setUris] = useState<string[]>(
    props.initialContent.data.uris.length > 0 ? props.initialContent.data.uris : [""]
  );
  const [showGenerator, setShowGenerator] = useState(false);

  if (showGenerator) {
    return (
      <GeneratorScreen
        onUse={(value) => {
          setPassword(value);
          setShowGenerator(false);
        }}
        onClose={() => {
          setShowGenerator(false);
        }}
      />
    );
  }

  function save() {
    return props.onSubmit({
      title,
      folder: props.initialContent.folder,
      favorite,
      custom_fields: customFields.filter((f) => f.label.trim() !== ""),
      data: {
        type: "login",
        username,
        password,
        uris: uris.filter((u) => u.trim() !== ""),
        notes,
      },
    });
  }

  return (
    <ItemFormChrome
      heading={props.mode === "create" ? t("item.login.newTitle") : t("item.login.editTitle")}
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
        {t("item.login.username")}
        <input
          type="text"
          autoComplete="username"
          value={username}
          onChange={(e) => {
            setUsername(e.target.value);
          }}
        />
      </label>
      <div className="auth-form__field">
        <label htmlFor="login-form-password">{t("item.login.password")}</label>
        <div className="item-form__password-row">
          <input
            id="login-form-password"
            type={showPassword ? "text" : "password"}
            autoComplete="new-password"
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
            }}
          />
          <button
            type="button"
            className="auth-form__link"
            onClick={() => {
              setShowPassword(!showPassword);
            }}
          >
            {showPassword ? t("item.common.hide") : t("item.common.reveal")}
          </button>
          <button
            type="button"
            className="auth-form__link"
            onClick={() => {
              copy(true, password);
            }}
          >
            {copiedKey === true ? t("item.common.copied") : t("item.common.copy")}
          </button>
          <button
            type="button"
            className="auth-form__link"
            onClick={() => {
              setShowGenerator(true);
            }}
          >
            {t("item.login.generate")}
          </button>
        </div>
        {password !== "" && <StrengthMeter bits={estimatePasswordEntropyBits(password)} />}
      </div>
      <fieldset className="item-form__fieldset">
        <legend>{t("item.login.uris")}</legend>
        {uris.map((uri, i) => (
          <div className="item-form__row" key={i}>
            <input
              type="text"
              value={uri}
              onChange={(e) => {
                setUris(uris.map((u, j) => (j === i ? e.target.value : u)));
              }}
            />
            <button
              type="button"
              className="auth-form__link"
              aria-label={t("item.login.removeUri")}
              onClick={() => {
                setUris(uris.filter((_, j) => j !== i));
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
            setUris([...uris, ""]);
          }}
        >
          {t("item.login.addUri")}
        </button>
      </fieldset>
      <label className="auth-form__field">
        {t("item.login.notes")}
        <textarea
          rows={3}
          value={notes}
          onChange={(e) => {
            setNotes(e.target.value);
          }}
        />
      </label>
    </ItemFormChrome>
  );
}
