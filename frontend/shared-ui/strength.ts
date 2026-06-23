// Stima di robustezza (doc 17 §3: "indicatore di robustezza coerente con quello
// dell'onboarding"). Condivisa tra la registrazione (master password) e il generatore,
// così i due indicatori restano coerenti per costruzione, non per convenzione separata
// mantenuta a mano in due punti.

export type Strength = "weak" | "fair" | "good" | "strong";

const LOWER = /[a-z]/;
const UPPER = /[A-Z]/;
const DIGIT = /[0-9]/;
const SYMBOL = /[^a-zA-Z0-9]/;
// Stessa cardinalità del set di simboli del generatore
// (`kunuk_crypto_core::generator::SYMBOLS`, frontend/desktop/src-tauri non lo espone
// come costante: tenerlo sincronizzato a mano è più semplice di un confine IPC per un
// numero).
const SYMBOL_SET_SIZE = 27;

/** Entropia stimata di una stringa digitata liberamente (master password, password
 * generata): cardinalità delle classi di carattere presenti elevata alla lunghezza. */
export function estimatePasswordEntropyBits(value: string): number {
  if (value.length === 0) return 0;
  let charsetSize = 0;
  if (LOWER.test(value)) charsetSize += 26;
  if (UPPER.test(value)) charsetSize += 26;
  if (DIGIT.test(value)) charsetSize += 10;
  if (SYMBOL.test(value)) charsetSize += SYMBOL_SET_SIZE;
  if (charsetSize === 0) return 0;
  return value.length * Math.log2(charsetSize);
}

/** Entropia esatta di una passphrase diceware: nota a priori (estrazione uniforme dal
 * CSPRNG, doc 16 §7), non va stimata dal testo come per una password digitata. */
export function passphraseEntropyBits(wordCount: number, wordlistSize: number): number {
  return wordCount * Math.log2(wordlistSize);
}

export function strengthFromEntropyBits(bits: number): Strength {
  if (bits < 40) return "weak";
  if (bits < 60) return "fair";
  if (bits < 80) return "good";
  return "strong";
}
