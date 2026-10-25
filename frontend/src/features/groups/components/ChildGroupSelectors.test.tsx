import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { Group } from "../../../types";
import { ChildGroupSelector, EditableChildGroupSelector } from "./ChildGroupSelectors";

const group = (id: string): Group => ({
  id,
  name: `Group ${id}`,
  code: `GRP-${id}`,
  description: null,
  scope_type: "GLOBAL",
  network_id: null,
  city_id: null,
  location_id: null,
  sector_id: null,
  device_scope: "ANY",
});

describe("Group child selectors", () => {
  it("preserves include-all child-group behavior", () => {
    const onAll = vi.fn();
    const onSelected = vi.fn();
    render(<ChildGroupSelector children={[group("1"), group("2")]} all={false} selected={[]} onAll={onAll} onSelected={onSelected} />);

    fireEvent.click(screen.getByRole("button", { name: /no child groups included/i }));
    const includeAll = screen.getByRole("checkbox", { name: /include all child groups/i });
    fireEvent.click(includeAll);

    expect(onAll).toHaveBeenCalledWith(true);
    expect(onSelected).toHaveBeenCalledWith([]);
  });

  it("preserves server-search and selected-count behavior for editable children", () => {
    const options = Array.from({ length: 11 }, (_, index) => group(String(index + 1)));
    const onSearch = vi.fn();
    render(
      <EditableChildGroupSelector
        options={options}
        total={25}
        baseTotal={25}
        selected={["1", "2"]}
        search=""
        onSearch={onSearch}
        onSelected={vi.fn()}
        loading={false}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /2 child groups selected/i }));
    const search = screen.getByPlaceholderText("Search eligible child groups...");
    fireEvent.change(search, { target: { value: "north" } });

    expect(onSearch).toHaveBeenCalledWith("north");
    expect(screen.getByText(/showing the first 11 matches/i)).toBeInTheDocument();
  });
});
