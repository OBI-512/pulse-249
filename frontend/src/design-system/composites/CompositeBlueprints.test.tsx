import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { Tabs } from "./Tabs";
import { ClearFiltersButton } from "./FilterBar";
import { EmptyState } from "./AsyncState";
import { PaginationControls } from "../data/Pagination";

describe("FR4 composite blueprints", () => {
  it("provides accessible reusable tabs", () => {
    const onChange = vi.fn();
    render(<Tabs tabs={[{id:"a",label:"A"},{id:"b",label:"B"}]} value="a" onChange={onChange}/>);
    fireEvent.click(screen.getByRole("tab", {name:"B"}));
    expect(onChange).toHaveBeenCalledWith("b");
  });
  it("keeps clear filters as an explicit action", () => {
    const onClick=vi.fn(); render(<ClearFiltersButton onClick={onClick}/>); fireEvent.click(screen.getByRole("button",{name:"Clear Filters"})); expect(onClick).toHaveBeenCalledTimes(1);
  });
  it("renders shared empty state", () => { render(<EmptyState text="Nothing here"/>); expect(screen.getByText("Nothing here")).toBeTruthy(); });
  it("hides pagination at 50 or fewer rows", () => {
    const {container}=render(<PaginationControls page={1} pageSize={50} total={50} onPage={()=>{}} onPageSize={()=>{}}/>); expect(container.firstChild).toBeNull();
  });
});
