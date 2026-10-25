import { describe, expect, it } from "vitest";
import networkPageSource from "./NetworkPage.tsx?raw";

describe("Location coordinate surfaces", () => {
  it("shows latitude and longitude in the Locations table", () => {
    expect(networkPageSource).toContain('<th>Address</th><th>Latitude</th><th>Longitude</th>');
    expect(networkPageSource).toContain('{row.latitude ??');
    expect(networkPageSource).toContain('{row.longitude ??');
    expect(networkPageSource).toContain('colSpan={10 + deleteColumn}');
  });
});