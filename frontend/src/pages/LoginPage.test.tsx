import { act, fireEvent, render, screen } from "@testing-library/react";
import { useState, type ComponentProps } from "react";
import { describe, expect, it, vi } from "vitest";
import { LoginPage } from "./LoginPage";

function renderLogin(overrides: Partial<ComponentProps<typeof LoginPage>> = {}) {
  const onSubmit = vi.fn();
  const props: ComponentProps<typeof LoginPage> = {
    username: "admin",
    password: "Admin123!",
    rememberMe: false,
    setUsername: vi.fn(),
    setPassword: vi.fn(),
    setRememberMe: vi.fn(),
    busy: false,
    error: "",
    onSubmit,
    ...overrides,
  };
  render(<LoginPage {...props} />);
  return { onSubmit, props };
}

function AutofillHarness() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  return (
    <LoginPage
      username={username}
      password={password}
      rememberMe={false}
      setUsername={setUsername}
      setPassword={setPassword}
      setRememberMe={() => undefined}
      busy={false}
      error=""
      onSubmit={() => undefined}
    />
  );
}

describe("LoginPage", () => {
  it("submits populated credentials", () => {
    const { onSubmit } = renderLogin();
    fireEvent.click(screen.getByRole("button", { name: /sign in/i }));
    expect(onSubmit).toHaveBeenCalledTimes(1);
  });

  it("disables sign-in when the username is blank", () => {
    renderLogin({ username: "" });
    expect(screen.getByRole("button", { name: /sign in/i })).toBeDisabled();
  });

  it("synchronizes silent browser autofill with the login state", () => {
    vi.useFakeTimers();
    try {
      render(<AutofillHarness />);

      const username = screen.getByLabelText("Username") as HTMLInputElement;
      const password = screen.getByLabelText("Password") as HTMLInputElement;
      const signIn = screen.getByRole("button", { name: /sign in/i });

      expect(signIn).toBeDisabled();

      username.value = "autofilled-user";
      password.value = "Autofilled123!";

      act(() => {
        vi.advanceTimersByTime(300);
      });

      expect(signIn).toBeEnabled();
    } finally {
      vi.useRealTimers();
    }
  });

  it("renders credential failures as an alert", () => {
    renderLogin({ error: "Wrong username or password." });
    expect(screen.getByRole("alert")).toHaveTextContent("Wrong username or password.");
  });
});
