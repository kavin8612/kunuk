import { useEffect, useState } from "react";
import type { ReactNode } from "react";
import { DEFAULT_AUTO_LOCK_MINUTES, useT } from "@kunuk/shared-ui";
import {
  createItem,
  deleteItem,
  getSettings,
  listItems,
  updateItem,
  type ItemContentDto,
  type ItemDataDto,
  type ItemSummary,
  type SecuritySettingsDto,
} from "../tauri";
import { AppShell } from "./AppShell";
import { LoginItemForm, type LoginContent } from "./LoginItemForm";
import { NoteItemForm, type NoteContent } from "./NoteItemForm";
import { CardItemForm, type CardContent } from "./CardItemForm";
import { IdentityItemForm, type IdentityContent } from "./IdentityItemForm";
import { FolderForm } from "./FolderForm";
import { GeneratorScreen } from "./GeneratorScreen";
import { SettingsScreen } from "./SettingsScreen";

interface Props {
  onLocked: () => void;
}

type NewKind = "login" | "secure_note" | "card" | "identity";

type Editor =
  | { kind: "none" }
  | { kind: "new"; itemType: NewKind }
  | { kind: "new-folder" }
  | { kind: "edit"; item: ItemSummary }
  | { kind: "generator" }
  | { kind: "settings" };

/** Voce coinvolta nella ricerca client-side (doc 17 §2): titolo, più lo stesso campo
 * già mostrato come sottotitolo in lista (username/email) — niente testo di note,
 * numeri di carta o campi personalizzati, per non far leva sulla ricerca per esporre
 * più di quanto la lista già mostri. */
function matchesQuery(item: ItemSummary, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (q === "") return true;
  const data = item.content.data;
  if (data.type === "folder") return false;
  if (item.content.title.toLowerCase().includes(q)) return true;
  if (data.type === "login") return data.username.toLowerCase().includes(q);
  if (data.type === "identity") return data.email.toLowerCase().includes(q);
  return false;
}

function isLoginContent(content: ItemContentDto): content is LoginContent {
  return content.data.type === "login";
}

function isNoteContent(content: ItemContentDto): content is NoteContent {
  return content.data.type === "secure_note";
}

function isCardContent(content: ItemContentDto): content is CardContent {
  return content.data.type === "card";
}

function isIdentityContent(content: ItemContentDto): content is IdentityContent {
  return content.data.type === "identity";
}

/** Sottotitolo della riga in lista: un indizio del contenuto senza aprire la voce (doc 17
 * §2) — niente per nota/cartella (il testo di una nota è il suo stesso segreto). */
function itemSubtitle(data: ItemDataDto): string | null {
  switch (data.type) {
    case "login":
      return data.username;
    case "identity":
      return data.email;
    case "card":
      return data.number.length >= 4 ? `•••• ${data.number.slice(-4)}` : data.number;
    case "secure_note":
    case "folder":
      return null;
  }
}

function newContent(itemType: NewKind, folder: string | null): ItemContentDto {
  const base = { title: "", folder, favorite: false, custom_fields: [] };
  switch (itemType) {
    case "login":
      return {
        ...base,
        data: { type: "login", username: "", password: "", uris: [], notes: "" },
      };
    case "secure_note":
      return { ...base, data: { type: "secure_note", text: "" } };
    case "card":
      return {
        ...base,
        data: {
          type: "card",
          cardholder_name: "",
          number: "",
          exp_month: 1,
          exp_year: new Date().getFullYear(),
          security_code: "",
        },
      };
    case "identity":
      return { ...base, data: { type: "identity", full_name: "", email: "", phone: "" } };
  }
}

/** Dispatch al form tipizzato giusto in base al tipo di voce — condiviso fra "new" ed
 * "edit" (stesse 4 branche, prima duplicate identiche tranne `mode`/`onDelete`/`onSubmit`). */
function renderItemForm(
  content: ItemContentDto,
  mode: "create" | "edit",
  onSubmit: (content: ItemContentDto) => Promise<void>,
  onCancel: () => void,
  onDelete?: () => Promise<void>
): ReactNode | undefined {
  // `exactOptionalPropertyTypes` (doc 19 §8) non ammette di assegnare esplicitamente
  // `undefined` a `onDelete?:` — va omesso del tutto in "new" (spread condizionale),
  // non passato come `undefined`.
  const deleteProp = onDelete !== undefined ? { onDelete } : {};
  if (isLoginContent(content)) {
    return (
      <LoginItemForm
        mode={mode}
        initialContent={content}
        onSubmit={onSubmit}
        onCancel={onCancel}
        {...deleteProp}
      />
    );
  }
  if (isNoteContent(content)) {
    return (
      <NoteItemForm
        mode={mode}
        initialContent={content}
        onSubmit={onSubmit}
        onCancel={onCancel}
        {...deleteProp}
      />
    );
  }
  if (isCardContent(content)) {
    return (
      <CardItemForm
        mode={mode}
        initialContent={content}
        onSubmit={onSubmit}
        onCancel={onCancel}
        {...deleteProp}
      />
    );
  }
  if (isIdentityContent(content)) {
    return (
      <IdentityItemForm
        mode={mode}
        initialContent={content}
        onSubmit={onSubmit}
        onCancel={onCancel}
        {...deleteProp}
      />
    );
  }
  return undefined;
}

/** Lista voci + cartelle/preferiti/campi personalizzati (C2, task 1.3): tutti i 4 tipi di
 * voce (Login/Nota/Carta/Identità). */
export function VaultScreen(props: Props) {
  const t = useT();
  const [items, setItems] = useState<ItemSummary[] | null>(null);
  const [loadError, setLoadError] = useState(false);
  const [folderStack, setFolderStack] = useState<ItemSummary[]>([]);
  const [editor, setEditor] = useState<Editor>({ kind: "none" });
  const [query, setQuery] = useState("");
  // Default solo per il primissimo render, in attesa della risposta di `get_settings`
  // (il valore vero è posseduto da Rust, non più da localStorage — doc 17 §9): l'auto-lock
  // parte comunque da subito con un timeout ragionevole, non disattivato.
  const [settings, setSettings] = useState<SecuritySettingsDto>({
    auto_lock_minutes: DEFAULT_AUTO_LOCK_MINUTES,
    clipboard_clear_seconds: 0,
  });

  const currentFolderItem = folderStack.at(-1);
  const currentFolder = currentFolderItem === undefined ? null : currentFolderItem.id;

  function refresh() {
    listItems()
      .then((result) => {
        setItems(result);
        setLoadError(false);
      })
      .catch(() => {
        setLoadError(true);
      });
  }

  useEffect(() => {
    refresh();
    getSettings()
      .then(setSettings)
      .catch(() => {
        /* il default resta attivo: l'auto-lock non deve mai restare disattivato per un
         * comando che non risponde */
      });
  }, []);

  function handleSettingsSaved(next: SecuritySettingsDto) {
    setSettings(next);
    closeEditor();
  }

  async function handleCreate(content: ItemContentDto) {
    await createItem(content);
    refresh();
    setEditor({ kind: "none" });
  }

  async function handleUpdate(id: string, content: ItemContentDto) {
    await updateItem(id, content);
    refresh();
    setEditor({ kind: "none" });
  }

  async function handleDelete(id: string) {
    await deleteItem(id);
    refresh();
    setEditor({ kind: "none" });
  }

  async function handleToggleFavorite(item: ItemSummary) {
    await updateItem(item.id, { ...item.content, favorite: !item.content.favorite });
    refresh();
  }

  function closeEditor() {
    setEditor({ kind: "none" });
  }

  // Corpo della schermata corrente, sempre avvolto da `AppShell` (in fondo alla funzione):
  // l'auto-lock e il blocco manuale restano attivi qualunque sia la sotto-schermata mostrata
  // qui (doc 17 §9), non solo la lista voci.
  let body: ReactNode | undefined;

  if (editor.kind === "new") {
    const content = newContent(editor.itemType, currentFolder);
    body = renderItemForm(content, "create", handleCreate, closeEditor);
  } else if (editor.kind === "new-folder") {
    body = <FolderForm folder={currentFolder} onSubmit={handleCreate} onCancel={closeEditor} />;
  } else if (editor.kind === "generator") {
    body = <GeneratorScreen onClose={closeEditor} />;
  } else if (editor.kind === "settings") {
    body = (
      <SettingsScreen settings={settings} onSaved={handleSettingsSaved} onCancel={closeEditor} />
    );
  } else if (editor.kind === "edit") {
    const editing = editor.item;
    body = renderItemForm(
      editing.content,
      "edit",
      (c) => handleUpdate(editing.id, c),
      closeEditor,
      () => handleDelete(editing.id)
    );
  }

  if (body === undefined) {
    const searching = query.trim() !== "";
    // La ricerca è globale (doc 17 §2: trovare una voce senza dover prima navigare le
    // cartelle); senza una query attiva si torna allo scoping per cartella corrente.
    const visible = (items ?? []).filter((i) =>
      searching ? matchesQuery(i, query) : i.content.folder === currentFolder
    );
    const folders = searching ? [] : visible.filter((i) => i.content.data.type === "folder");
    const entries = searching ? visible : visible.filter((i) => i.content.data.type !== "folder");

    body = (
      <div className="vault">
        <header className="vault__header">
          <h1>{t("vault.title")}</h1>
          <div className="vault__header-actions">
            <button
              type="button"
              onClick={() => {
                setEditor({ kind: "generator" });
              }}
            >
              {t("vault.generator")}
            </button>
            <button
              type="button"
              onClick={() => {
                setEditor({ kind: "settings" });
              }}
            >
              {t("vault.settings")}
            </button>
          </div>
        </header>
        <input
          type="search"
          className="vault__search"
          placeholder={t("vault.search")}
          aria-label={t("vault.search")}
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
          }}
        />
        <div className="vault__toolbar">
          {!searching && folderStack.length > 0 && (
            <button
              type="button"
              className="auth-form__link"
              onClick={() => {
                setFolderStack(folderStack.slice(0, -1));
              }}
            >
              {t("vault.back")}
            </button>
          )}
          <button
            type="button"
            className="auth-form__link"
            onClick={() => {
              setEditor({ kind: "new", itemType: "login" });
            }}
          >
            {t("vault.addLogin")}
          </button>
          <button
            type="button"
            className="auth-form__link"
            onClick={() => {
              setEditor({ kind: "new", itemType: "secure_note" });
            }}
          >
            {t("vault.addNote")}
          </button>
          <button
            type="button"
            className="auth-form__link"
            onClick={() => {
              setEditor({ kind: "new", itemType: "card" });
            }}
          >
            {t("vault.addCard")}
          </button>
          <button
            type="button"
            className="auth-form__link"
            onClick={() => {
              setEditor({ kind: "new", itemType: "identity" });
            }}
          >
            {t("vault.addIdentity")}
          </button>
          <button
            type="button"
            className="auth-form__link"
            onClick={() => {
              setEditor({ kind: "new-folder" });
            }}
          >
            {t("vault.addFolder")}
          </button>
        </div>
        {items === null && !loadError && <p className="vault__empty">{t("vault.loading")}</p>}
        {loadError && <p className="vault__empty">{t("vault.loadError")}</p>}
        {items !== null && visible.length === 0 && (
          <p className="vault__empty">{searching ? t("vault.noResults") : t("vault.empty")}</p>
        )}
        <ul className="vault__list">
          {folders.map((folder) => (
            <li className="vault__row" key={folder.id}>
              <button
                type="button"
                className="vault__row-main"
                onClick={() => {
                  setFolderStack([...folderStack, folder]);
                }}
              >
                📁 {folder.content.title}
              </button>
            </li>
          ))}
          {entries.map((item) => {
            const subtitle = itemSubtitle(item.content.data);
            return (
              <li className="vault__row" key={item.id}>
                <button
                  type="button"
                  className="vault__row-main"
                  onClick={() => {
                    setEditor({ kind: "edit", item });
                  }}
                >
                  <span className="vault__row-title">{item.content.title}</span>
                  {subtitle !== null && <span className="vault__row-subtitle">{subtitle}</span>}
                </button>
                <button
                  type="button"
                  className="vault__row-favorite"
                  aria-label={
                    item.content.favorite ? t("vault.favoriteOn") : t("vault.favoriteOff")
                  }
                  onClick={() => void handleToggleFavorite(item)}
                >
                  {item.content.favorite ? "★" : "☆"}
                </button>
              </li>
            );
          })}
        </ul>
      </div>
    );
  }

  return (
    <AppShell autoLockMinutes={settings.auto_lock_minutes} onLocked={props.onLocked}>
      {body}
    </AppShell>
  );
}
