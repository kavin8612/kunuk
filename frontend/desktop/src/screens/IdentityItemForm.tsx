import { useState } from "react";
import { useT } from "@kunuk/shared-ui";
import { ItemFormChrome } from "./ItemFormChrome";
import type { CustomFieldDto, ItemContentDto, ItemDataDto } from "../tauri";

export type IdentityContent = ItemContentDto & {
  data: Extract<ItemDataDto, { type: "identity" }>;
};

interface Props {
  mode: "create" | "edit";
  initialContent: IdentityContent;
  onSubmit: (content: IdentityContent) => Promise<void>;
  onDelete?: () => Promise<void>;
  onCancel: () => void;
}

/** Form di creazione/modifica di un'identità (C2, task #15): nome completo, email, telefono
 * come campi tipizzati; il resto è l'involucro comune (`ItemFormChrome`). */
export function IdentityItemForm(props: Props) {
  const t = useT();
  const [title, setTitle] = useState(props.initialContent.title);
  const [favorite, setFavorite] = useState(props.initialContent.favorite);
  const [customFields, setCustomFields] = useState<CustomFieldDto[]>(
    props.initialContent.custom_fields
  );
  const [fullName, setFullName] = useState(props.initialContent.data.full_name);
  const [email, setEmail] = useState(props.initialContent.data.email);
  const [phone, setPhone] = useState(props.initialContent.data.phone);

  function save() {
    return props.onSubmit({
      title,
      folder: props.initialContent.folder,
      favorite,
      custom_fields: customFields.filter((f) => f.label.trim() !== ""),
      data: { type: "identity", full_name: fullName, email, phone },
    });
  }

  return (
    <ItemFormChrome
      heading={props.mode === "create" ? t("item.identity.newTitle") : t("item.identity.editTitle")}
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
        {t("item.identity.fullName")}
        <input
          type="text"
          autoComplete="name"
          value={fullName}
          onChange={(e) => {
            setFullName(e.target.value);
          }}
        />
      </label>
      <label className="auth-form__field">
        {t("item.identity.email")}
        <input
          type="email"
          autoComplete="email"
          value={email}
          onChange={(e) => {
            setEmail(e.target.value);
          }}
        />
      </label>
      <label className="auth-form__field">
        {t("item.identity.phone")}
        <input
          type="tel"
          autoComplete="tel"
          value={phone}
          onChange={(e) => {
            setPhone(e.target.value);
          }}
        />
      </label>
    </ItemFormChrome>
  );
}
