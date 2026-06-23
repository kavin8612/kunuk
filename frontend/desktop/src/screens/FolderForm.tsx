import { useState } from "react";
import type { SyntheticEvent } from "react";
import { useT } from "@kunuk/shared-ui";
import type { ItemContentDto } from "../tauri";

interface Props {
  folder: string | null;
  onSubmit: (content: ItemContentDto) => Promise<void>;
  onCancel: () => void;
}

/** Form di creazione di una cartella: una voce come le altre (ADR-0021), solo il nome. */
export function FolderForm(props: Props) {
  const t = useT();
  const [title, setTitle] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  function handleSubmit(e: SyntheticEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setPending(true);
    props
      .onSubmit({
        title,
        folder: props.folder,
        favorite: false,
        custom_fields: [],
        data: { type: "folder" },
      })
      .catch(() => {
        setError(t("auth.error.generic"));
      })
      .finally(() => {
        setPending(false);
      });
  }

  return (
    <form className="auth-form item-form" onSubmit={handleSubmit}>
      <h1 className="auth-form__title">{t("item.folder.newTitle")}</h1>
      <label className="auth-form__field">
        {t("item.folder.name")}
        <input
          type="text"
          required
          value={title}
          onChange={(e) => {
            setTitle(e.target.value);
          }}
        />
      </label>
      {error !== null && <p className="auth-form__error">{error}</p>}
      <div className="item-form__actions">
        <button type="submit" className="auth-form__primary" disabled={pending}>
          {t("item.folder.save")}
        </button>
        <button type="button" className="auth-form__link" onClick={props.onCancel}>
          {t("vault.cancel")}
        </button>
      </div>
    </form>
  );
}
