import { useState } from "react";
import type { SyntheticEvent } from "react";
import { useT } from "@kunuk/shared-ui";
import { login } from "../tauri";

interface Props {
  onUnlocked: () => void;
  onSwitchToRegister: () => void;
}

export function LoginScreen(props: Props) {
  const t = useT();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [secretKey, setSecretKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);

  function handleSubmit(e: SyntheticEvent<HTMLFormElement>) {
    e.preventDefault();
    setError(null);
    setPending(true);
    login(email, password, secretKey)
      .then(props.onUnlocked)
      .catch(() => {
        setError(t("auth.error.generic"));
      })
      .finally(() => {
        setPending(false);
      });
  }

  return (
    <form className="auth-form" onSubmit={handleSubmit}>
      <h1 className="auth-form__title">{t("auth.login.title")}</h1>
      <label className="auth-form__field">
        {t("auth.login.email")}
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
        {t("auth.login.password")}
        <input
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(e) => {
            setPassword(e.target.value);
          }}
        />
      </label>
      <div className="auth-form__field">
        <label htmlFor="login-form-secret-key">{t("auth.login.secretKey")}</label>
        <input
          id="login-form-secret-key"
          type="text"
          spellCheck={false}
          required
          value={secretKey}
          onChange={(e) => {
            setSecretKey(e.target.value);
          }}
        />
        <span className="auth-form__hint">{t("auth.login.secretKeyHint")}</span>
      </div>
      {error !== null && <p className="auth-form__error">{error}</p>}
      <button type="submit" className="auth-form__primary" disabled={pending}>
        {t("auth.login.submit")}
      </button>
      <button type="button" className="auth-form__link" onClick={props.onSwitchToRegister}>
        {t("auth.login.switchToRegister")}
      </button>
    </form>
  );
}
