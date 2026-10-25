import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { StatCard } from ".";
import { StatusBadge } from "../Status";

describe("metric and status blueprints", () => {
  it("renders the canonical stat card", () => {
    render(<StatCard label="Database" value="online" detail="PostgreSQL" />);
    expect(screen.getByText("Database")).toBeTruthy();
    expect(screen.getByText("online")).toBeTruthy();
  });

  it("preserves the domain status badge class contract", () => {
    const { container } = render(<StatusBadge value="ACTIVE" />);
    expect(container.querySelector(".badge-active")).toBeTruthy();
  });
});
