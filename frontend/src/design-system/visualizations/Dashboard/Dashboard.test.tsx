import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AvailabilityGauge, DashboardMetricCard } from ".";

describe("dashboard visualization blueprints", () => {
  it("renders a metric card without changing its legacy semantic contract", () => {
    render(<DashboardMetricCard icon="devices" label="Managed" value={1234} detail="Monitored inventory" tone="blue" />);
    expect(screen.getByText("Managed")).toBeTruthy();
    expect(screen.getByText("1,234")).toBeTruthy();
  });

  it("renders an availability gauge with an accessible label", () => {
    render(<AvailabilityGauge label="CPEs" online={75} total={100} />);
    expect(screen.getByLabelText("CPEs: 75 of 100 online")).toBeTruthy();
    expect(screen.getByText("75%")).toBeTruthy();
  });
});
