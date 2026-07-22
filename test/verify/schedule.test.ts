import { describe, it, expect } from "vitest";
import {
  nextDelayMs,
  FAST_INTERVAL_MS,
  FAST_PHASE_MS,
  MAX_ELAPSED_MS,
} from "../../src/verify/schedule";

const MIN = 60_000;

describe("nextDelayMs — fast phase (first 2 min → 10s)", () => {
  it("at start returns 10s", () => {
    expect(nextDelayMs(0)).toBe(FAST_INTERVAL_MS);
    expect(nextDelayMs(0)).toBe(10_000);
  });

  it("just before the 2-min boundary still 10s", () => {
    expect(nextDelayMs(FAST_PHASE_MS - 1)).toBe(10_000);
  });
});

describe("nextDelayMs — backoff (1/2/4/8 min)", () => {
  it("at 2 min → 1 min", () => {
    expect(nextDelayMs(2 * MIN)).toBe(1 * MIN);
  });

  it("just before 3 min → still 1 min", () => {
    expect(nextDelayMs(3 * MIN - 1)).toBe(1 * MIN);
  });

  it("at 3 min → 2 min", () => {
    expect(nextDelayMs(3 * MIN)).toBe(2 * MIN);
  });

  it("at 5 min → 4 min", () => {
    expect(nextDelayMs(5 * MIN)).toBe(4 * MIN);
  });

  it("at 9 min → holds at 8 min", () => {
    expect(nextDelayMs(9 * MIN)).toBe(8 * MIN);
  });

  it("deep into the steady phase → still 8 min", () => {
    expect(nextDelayMs(10 * 60 * MIN)).toBe(8 * MIN);
  });
});

describe("nextDelayMs — 72h cap", () => {
  it("just before the cap → still polling (8 min)", () => {
    expect(nextDelayMs(MAX_ELAPSED_MS - 1)).toBe(8 * MIN);
  });

  it("at the cap → null (give up)", () => {
    expect(nextDelayMs(MAX_ELAPSED_MS)).toBeNull();
  });

  it("past the cap → null", () => {
    expect(nextDelayMs(MAX_ELAPSED_MS + 1_000_000)).toBeNull();
  });

  it("cap is exactly 72h", () => {
    expect(MAX_ELAPSED_MS).toBe(72 * 60 * 60 * 1000);
  });
});
