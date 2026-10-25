import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ActionBar, Card, DashboardLayout, DetailViewLayout, ListViewLayout, PageHeader, Panel, SectionHeader, SectionStack, SettingsLayout, SplitView } from ".";

describe("FR5 layout blueprints", () => {
  it("renders canonical page and section headers with actions and help", () => {
    render(<><PageHeader title="Devices" help="Device help" actions={<button>Refresh</button>} /><SectionHeader title="Inventory" help="Inventory help" actions={<button>Export</button>} /></>);
    expect(screen.getByRole("heading", { name: "Devices" })).toHaveAttribute("data-help", "Device help");
    expect(screen.getByRole("heading", { name: "Inventory" })).toHaveAttribute("data-help", "Inventory help");
    expect(screen.getByRole("button", { name: "Refresh" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Export" })).toBeInTheDocument();
  });

  it("provides list/detail/dashboard/settings and split composition", () => {
    render(<><ListViewLayout><span>list</span></ListViewLayout><DetailViewLayout><span>detail</span></DetailViewLayout><DashboardLayout><span>dashboard</span></DashboardLayout><SettingsLayout><span>settings</span></SettingsLayout><SplitView primary={<span>primary</span>} secondary={<span>secondary</span>} /></>);
    for (const text of ["list","detail","dashboard","settings","primary","secondary"]) expect(screen.getByText(text)).toBeInTheDocument();
  });

  it("provides reusable panel/card/stack/action surfaces", () => {
    render(<SectionStack><Panel><span>panel</span></Panel><Card><span>card</span></Card><ActionBar><button>Do it</button></ActionBar></SectionStack>);
    expect(screen.getByText("panel")).toBeInTheDocument();
    expect(screen.getByText("card")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Do it" }));
  });
});
