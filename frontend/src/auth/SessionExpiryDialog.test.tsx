import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { SessionExpiryDialog } from "./SessionExpiryDialog";

describe("SessionExpiryDialog", () => {
  it("shows the expiry countdown and explicit extend/logout actions", () => {
    const extend = vi.fn();
    const decline = vi.fn();
    render(
      <SessionExpiryDialog
        offer={{ expiresAt: "2030-01-01T08:00:00Z", secondsRemaining: 300, renewalMinutes: 480 }}
        busy={false}
        onExtend={extend}
        onDecline={decline}
      />,
    );
    expect(screen.getByRole("dialog", { name: "Session about to expire" })).toBeInTheDocument();
    expect(screen.getByText("05:00")).toBeInTheDocument();
    expect(screen.getByText(/another 8 hours/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Extend session" }));
    fireEvent.click(screen.getByRole("button", { name: "Not now" }));
    expect(extend).toHaveBeenCalledTimes(1);
    expect(decline).toHaveBeenCalledTimes(1);
  });
});
