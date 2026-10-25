import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Tabs } from "./Tabs";

describe("canonical Tabs blueprint", () => {
  it("exposes accessible selection and change behavior", () => {
    const onChange = vi.fn();
    render(
      <Tabs
        ariaLabel="Example views"
        tabs={[{ id: "one", label: "One" }, { id: "two", label: "Two" }]}
        value="one"
        onChange={onChange}
      />,
    );
    expect(screen.getByRole("tablist", { name: "Example views" })).toBeTruthy();
    expect(screen.getByRole("tab", { name: "One" }).getAttribute("aria-selected")).toBe("true");
    fireEvent.click(screen.getByRole("tab", { name: "Two" }));
    expect(onChange).toHaveBeenCalledWith("two");
  });

  it("keeps hidden tabs out and disabled tabs non-interactive", () => {
    const onChange = vi.fn();
    render(
      <Tabs
        tabs={[
          { id: "one", label: "One" },
          { id: "hidden", label: "Hidden", visible: false },
          { id: "locked", label: "Locked", disabled: true },
        ]}
        value="one"
        onChange={onChange}
      />,
    );
    expect(screen.queryByRole("tab", { name: "Hidden" })).toBeNull();
    const locked = screen.getByRole("tab", { name: "Locked" });
    expect((locked as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(locked);
    expect(onChange).not.toHaveBeenCalled();
  });
  it("keeps the selected tab stable and preserves option titles", () => {
    const onChange = vi.fn();
    render(
      <Tabs
        tabs={[{ id: "one", label: "One", title: "Current view" }, { id: "two", label: "Two" }]}
        value="one"
        onChange={onChange}
      />,
    );
    const selected = screen.getByRole("tab", { name: "One" });
    expect(selected.getAttribute("title")).toBe("Current view");
    fireEvent.click(selected);
    expect(onChange).not.toHaveBeenCalled();
  });

  it("supports theme-preserving closable application tabs", () => {
    const onChange = vi.fn();
    const onClose = vi.fn();
    render(
      <Tabs
        tabs={[{ id: "reports", label: "Reports" }, { id: "edit", label: "Edit Test Report", closable: true }]}
        value="edit"
        onChange={onChange}
        onClose={onClose}
      />,
    );
    expect(screen.getByRole("tab", { name: "Edit Test Report" }).getAttribute("aria-selected")).toBe("true");
    fireEvent.click(screen.getByRole("button", { name: "Close Edit Test Report" }));
    expect(onClose).toHaveBeenCalledWith("edit");
  });

});
