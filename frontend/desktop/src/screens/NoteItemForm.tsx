import { useState } from "react";
import { useT } from "@kunuk/shared-ui";
import { ItemFormChrome } from "./ItemFormChrome";
import type { CustomFieldDto, ItemContentDto, ItemDataDto } from "../tauri";

export type NoteContent = ItemContentDto & {
  data: Extract<ItemDataDto, { type: "secure_note" }>;
};

interface Props {
  mode: "create" | "edit";
  initialContent: NoteContent;
  onSubmit: (content: NoteContent) => Promise<void>;
  onDelete?: () => Promise<void>;
  onCancel: () => void;
}

/** Form di creazione/modifica di una nota sicura (C2, task #15): solo il testo come campo
 * tipizzato, il resto è l'involucro comune (`ItemFormChrome`). */
export function NoteItemForm(props: Props) {
  const t = useT();
  const [title, setTitle] = useState(props.initialContent.title);
  const [favorite, setFavorite] = useState(props.initialContent.favorite);
  const [customFields, setCustomFields] = useState<CustomFieldDto[]>(
    props.initialContent.custom_fields
  );
  const [text, setText] = useState(props.initialContent.data.text);

  function save() {
    return props.onSubmit({
      title,
      folder: props.initialContent.folder,
      favorite,
      custom_fields: customFields.filter((f) => f.label.trim() !== ""),
      data: { type: "secure_note", text },
    });
  }

  return (
    <ItemFormChrome
      heading={props.mode === "create" ? t("item.note.newTitle") : t("item.note.editTitle")}
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
        {t("item.note.text")}
        <textarea
          rows={8}
          value={text}
          onChange={(e) => {
            setText(e.target.value);
          }}
        />
      </label>
    </ItemFormChrome>
  );
}
