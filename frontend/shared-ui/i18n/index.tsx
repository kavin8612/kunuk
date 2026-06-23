import { createContext, useContext, useMemo } from "react";
import type { ReactNode } from "react";
import type { Catalog, Locale } from "./catalog";
import { it } from "./it";
import { en } from "./en";

export type { Catalog, Locale } from "./catalog";

const catalogs: Record<Locale, Catalog> = { it, en };

/** Lingua predefinita se quella del sistema non è supportata (doc 17 §13: italiano è la lingua di lavoro). */
const FALLBACK_LOCALE: Locale = "it";

/** Riconosce la lingua del sistema tra quelle supportate; altrimenti FALLBACK_LOCALE. */
export function detectLocale(navigatorLanguage: string): Locale {
  const short = navigatorLanguage.slice(0, 2).toLowerCase();
  return short in catalogs ? (short as Locale) : FALLBACK_LOCALE;
}

const LocaleContext = createContext<Locale>(FALLBACK_LOCALE);

export function I18nProvider(props: { locale: Locale; children: ReactNode }) {
  return <LocaleContext.Provider value={props.locale}>{props.children}</LocaleContext.Provider>;
}

/** Restituisce `t(key)`: la stringa del catalogo della lingua attiva per quella chiave. */
export function useT(): (key: keyof Catalog) => string {
  const locale = useContext(LocaleContext);
  const catalog = catalogs[locale];
  return useMemo(() => (key: keyof Catalog) => catalog[key], [catalog]);
}
