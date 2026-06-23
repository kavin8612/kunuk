import { useState } from "react";
import type { SyntheticEvent } from "react";
import { useT } from "@kunuk/shared-ui";
import { estimatePasswordEntropyBits } from "@kunuk/shared-ui";
import { register } from "../tauri";
import { StrengthMeter } from "../components/StrengthMeter";

interface Props {
  onRegistered: (secretKey: string) => void;
  onSwitchToLogin: () => void;
}

export function RegisterScreen(props: Props) {
  const t = useT();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  function handleSubmit(e: SyntheticEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setPending(true);
    register(email, password)
      .then((result) => {
        props.onRegistered(result.secret_key);
      })
      .catch(() => {
        setError(t("auth.error.generic"));
      })
      .finally(() => {
        setPending(false);
      });
  }

  return (
    <form className="auth-form" onSubmit={handleSubmit}>
      <h1 className="auth-form__title">{t("auth.register.title")}</h1>
      <label className="auth-form__field">
        {t("auth.register.email")}
        <input
          type="email"
          autoComplete="email"
          required
          value={email}
          onChange={(e) => {
            setEmail(e.target.value);
          }}
        />
      </label>
      <label className="auth-form__field">
        {t("auth.register.password")}
        <input
          type="password"
          autoComplete="new-password"
          required
          value={password}
          onChange={(e) => {
            setPassword(e.target.value);
          }}
        />
      </label>
      {password !== "" && <StrengthMeter bits={estimatePasswordEntropyBits(password)} />}
      {error !== null && <p className="auth-form__error">{error}</p>}
      <button type="submit" className="auth-form__primary" disabled={pending}>
        {t("auth.register.submit")}
      </button>
      <button type="button" className="auth-form__link" onClick={props.onSwitchToLogin}>
        {t("auth.register.switchToLogin")}
      </button>
    </form>
  );
}
