// Wrapper tipati sui comandi Tauri (doc 20 §1): qui non c'è mai un byte di chiave, solo
// stringhe opache (email, password, Secret Key in transito verso Rust) e risultati già
// sicuri da mostrare (es. la Secret Key in chiaro, esposizione one-shot dell'EmergencyKit).
import { invoke } from "@tauri-apps/api/core";

export interface RegisterResult {
  secret_key: string;
}

export function register(email: string, password: string): Promise<RegisterResult> {
  return invoke("register", { email, password });
}

export function login(email: string, password: string, secretKey: string): Promise<void> {
  return invoke("login", { email, password, secretKey });
}

export function lock(): Promise<void> {
  return invoke("lock");
}

export function isUnlocked(): Promise<boolean> {
  return invoke("is_unlocked");
}

// Mirror di `AppSettings` (`src-tauri/src/settings.rs`, snake_case come gli altri DTO sopra):
// timeout di auto-lock/clipboard, posseduti e clampati da Rust — il renderer li legge/scrive
// solo tramite questi comandi, mai da `localStorage` (scoperto in code review, doc 17 §9).
export interface SecuritySettingsDto {
  auto_lock_minutes: number;
  clipboard_clear_seconds: number;
}

export function getSettings(): Promise<SecuritySettingsDto> {
  return invoke("get_settings");
}

export function saveSettings(settings: SecuritySettingsDto): Promise<SecuritySettingsDto> {
  return invoke("save_settings", { settings });
}

// Mirror di `kunuk_crypto_core::vault::item::{ItemContent, ItemData, CustomField}` (via i DTO
// di `items.rs`): nomi di campo snake_case perché qui non c'è un `rename_all` lato Rust, a
// differenza dei parametri dei comandi (quelli sì auto-convertiti in camelCase da Tauri).
export interface CustomFieldDto {
  label: string;
  value: string;
  hidden: boolean;
}

export type ItemDataDto =
  | { type: "login"; username: string; password: string; uris: string[]; notes: string }
  | { type: "secure_note"; text: string }
  | {
      type: "card";
      cardholder_name: string;
      number: string;
      exp_month: number;
      exp_year: number;
      security_code: string;
    }
  | { type: "identity"; full_name: string; email: string; phone: string }
  | { type: "folder" };

export interface ItemContentDto {
  title: string;
  folder: string | null;
  favorite: boolean;
  custom_fields: CustomFieldDto[];
  data: ItemDataDto;
}

export interface ItemSummary {
  id: string;
  content: ItemContentDto;
}

export function listItems(): Promise<ItemSummary[]> {
  return invoke("list_items");
}

export function createItem(content: ItemContentDto): Promise<ItemSummary> {
  return invoke("create_item", { content });
}

export function updateItem(id: string, content: ItemContentDto): Promise<void> {
  return invoke("update_item", { id, content });
}

export function deleteItem(id: string): Promise<void> {
  return invoke("delete_item", { id });
}

// Mirror di `kunuk_crypto_core::generator::PasswordPolicy` (snake_case, stesso confine
// IPC interno di `ItemContentDto` sopra).
export interface PasswordPolicyDto {
  length: number;
  uppercase: boolean;
  lowercase: boolean;
  numbers: boolean;
  symbols: boolean;
  exclude_ambiguous: boolean;
}

export function generatePassword(policy: PasswordPolicyDto): Promise<string> {
  return invoke("generate_password", { policy });
}

export type PassphraseLang = "it" | "en";

export function generatePassphrase(
  lang: PassphraseLang,
  words: number,
  separator: string
): Promise<string> {
  return invoke("generate_passphrase", { lang, words, separator });
}
