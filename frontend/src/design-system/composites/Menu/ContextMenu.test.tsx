import { describe, expect, it } from "vitest";

import { computeContextMenuPosition } from "./ContextMenu";

describe("computeContextMenuPosition", () => {
  it("keeps the normal menu eight pixels to the right and below the pointer", () => {
    expect(computeContextMenuPosition(
      { x: 100, y: 100 },
      { width: 200, height: 120 },
      { width: 800, height: 600 },
    )).toEqual({ x: 108, y: 108 });
  });

  it("flips left and up when the right and bottom edges would collide", () => {
    expect(computeContextMenuPosition(
      { x: 790, y: 590 },
      { width: 200, height: 120 },
      { width: 800, height: 600 },
    )).toEqual({ x: 582, y: 462 });
  });

  it("flips only the axis that collides", () => {
    expect(computeContextMenuPosition(
      { x: 790, y: 100 },
      { width: 200, height: 120 },
      { width: 800, height: 600 },
    )).toEqual({ x: 582, y: 108 });
  });

  it("uses the viewport margin as a final safety when the menu cannot fit around the pointer", () => {
    expect(computeContextMenuPosition(
      { x: 50, y: 50 },
      { width: 200, height: 200 },
      { width: 100, height: 100 },
    )).toEqual({ x: 8, y: 8 });
  });
});
