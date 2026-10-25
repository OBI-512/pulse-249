import { describe, expect, it } from "vitest";
import devicePageSource from "./DevicePage.tsx?raw";
import topologyPageSource from "./TopologyPage.tsx?raw";
import menuSource from "../design-system/composites/Menu/ContextMenu.tsx?raw";

describe("Batch C context-menu convergence", () => {
  it("uses the controlled design-system surface for inventory rows", () => {
    expect(devicePageSource).toContain("ContextMenuSurface");
    expect(devicePageSource).not.toContain("createPortal");
    expect(devicePageSource).not.toContain("menuPosition");
    expect(devicePageSource).not.toContain("menuRef");
  });

  it("keeps topology on the same design-system context-menu implementation", () => {
    expect(topologyPageSource).toContain("<ContextMenu items={deviceMenuItems");
    expect(topologyPageSource).toContain("from \"../design-system/composites/Menu\"");
  });

  it("uses collision-aware flipping before final viewport clamping", () => {
    expect(menuSource).toContain("anchor.x - CONTEXT_MENU_GAP - menuSize.width");
    expect(menuSource).toContain("anchor.y - CONTEXT_MENU_GAP - menuSize.height");
    expect(menuSource).toContain("viewport.width - menuSize.width - CONTEXT_MENU_MARGIN");
    expect(menuSource).toContain("viewport.height - menuSize.height - CONTEXT_MENU_MARGIN");
  });
});
