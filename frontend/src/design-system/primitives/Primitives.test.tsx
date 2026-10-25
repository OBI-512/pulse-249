import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Badge, Button, Checkbox, IconButton, Input, Select, Spinner, Tooltip } from ".";

describe("design-system primitives", () => {
  it("Button is semantic, typed by variant and disables while loading", () => {
    const click = vi.fn();
    render(<Button variant="secondary" loading onClick={click}>Save</Button>);
    const button = screen.getByRole("button", { name: "Working..." });
    expect(button).toBeDisabled();
    fireEvent.click(button);
    expect(click).not.toHaveBeenCalled();
  });

  it("IconButton requires an accessible label", () => {
    render(<IconButton label="Close" icon={<span>X</span>} />);
    expect(screen.getByRole("button", { name: "Close" })).toBeInTheDocument();
  });

  it("Input and Select expose invalid state", () => {
    render(<><Input aria-label="Name" invalid /><Select aria-label="Type" invalid><option>A</option></Select></>);
    expect(screen.getByLabelText("Name")).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByLabelText("Type")).toHaveAttribute("aria-invalid", "true");
  });

  it("Checkbox renders an associated text label", () => {
    render(<Checkbox label="Enabled" />);
    expect(screen.getByRole("checkbox", { name: "Enabled" })).toBeInTheDocument();
  });

  it("Badge, Tooltip and Spinner expose their intended semantics", () => {
    render(<><Badge tone="success">Online</Badge><Tooltip content="More information"><button type="button">Info</button></Tooltip><Spinner label="Collecting" /></>);
    expect(screen.getByText("Online")).toBeInTheDocument();
    expect(screen.getByRole("tooltip")).toHaveTextContent("More information");
    expect(screen.getByRole("status", { name: "Collecting" })).toBeInTheDocument();
  });
});
