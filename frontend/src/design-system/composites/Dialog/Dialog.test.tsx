import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { DialogActions, DialogBackdrop, DialogCard, DialogHeader, DialogMessage } from "./Dialog";

describe("Dialog blueprint", () => {
  it("preserves the established project dialog class contract", () => {
    const close = vi.fn();
    render(
      <DialogBackdrop data-testid="backdrop">
        <DialogCard danger role="dialog">
          <DialogHeader eyebrow="CONFIRMATION" title="Delete item" onClose={close} />
          <DialogMessage>Continue?</DialogMessage>
          <DialogActions><button type="button">Cancel</button></DialogActions>
        </DialogCard>
      </DialogBackdrop>,
    );
    expect(screen.getByTestId("backdrop")).toHaveClass("dialog-backdrop");
    expect(screen.getByRole("dialog")).toHaveClass("dialog-card", "dialog-danger");
    expect(screen.getByText("Continue?")).toHaveClass("dialog-message");
    fireEvent.click(screen.getByRole("button", { name: "Close dialog" }));
    expect(close).toHaveBeenCalledTimes(1);
  });
});
