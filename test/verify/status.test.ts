import { describe, it, expect } from "vitest";
import {
  recordStatus,
  rollupStatus,
  type RecordObservation,
} from "../../src/verify/status";
import type { RecordVerifyState } from "../../src/types";

const obs = (o: Partial<RecordObservation>): RecordObservation => ({
  confirmed: 0,
  total: 0,
  errors: 0,
  ...o,
});

describe("recordStatus — external zone (no authoritative signal)", () => {
  it("all resolvers confirm → published", () => {
    expect(recordStatus(obs({ confirmed: 2, total: 2 }))).toBe("published");
  });

  it("some resolvers confirm, others stale → propagating", () => {
    expect(recordStatus(obs({ confirmed: 1, total: 2 }))).toBe("propagating");
  });

  it("no resolver confirms (clean answers, record absent) → pending", () => {
    expect(recordStatus(obs({ confirmed: 0, total: 2 }))).toBe("pending");
  });

  it("every queried resolver hard-errored → failed", () => {
    expect(recordStatus(obs({ confirmed: 0, total: 0, errors: 2 }))).toBe(
      "failed",
    );
  });

  it("nothing queried at all → pending (not failed)", () => {
    expect(recordStatus(obs({}))).toBe("pending");
  });

  it("one resolver errored but another confirmed → still published", () => {
    expect(recordStatus(obs({ confirmed: 1, total: 1, errors: 1 }))).toBe(
      "published",
    );
  });
});

describe("recordStatus — owned zone (authoritative read-back wins)", () => {
  it("authoritative confirms AND public caught up → published", () => {
    expect(
      recordStatus(obs({ authoritativeConfirmed: true, confirmed: 2, total: 2 })),
    ).toBe("published");
  });

  it("authoritative confirms but public still stale → propagating", () => {
    expect(
      recordStatus(obs({ authoritativeConfirmed: true, confirmed: 0, total: 2 })),
    ).toBe("propagating");
  });

  it("authoritative confirms with no public signal yet → propagating", () => {
    expect(
      recordStatus(obs({ authoritativeConfirmed: true, confirmed: 0, total: 0 })),
    ).toBe("propagating");
  });

  it("authoritative says absent, public also absent → pending", () => {
    expect(
      recordStatus(obs({ authoritativeConfirmed: false, confirmed: 0, total: 2 })),
    ).toBe("pending");
  });

  it("authoritative absent but a public resolver saw it early → propagating", () => {
    expect(
      recordStatus(obs({ authoritativeConfirmed: false, confirmed: 1, total: 2 })),
    ).toBe("propagating");
  });

  it("authoritative confirm overrides an all-error public view", () => {
    expect(
      recordStatus(obs({ authoritativeConfirmed: true, total: 0, errors: 2 })),
    ).toBe("propagating");
  });
});

describe("rollupStatus", () => {
  const rec = (status: RecordVerifyState["status"]): RecordVerifyState => ({
    type: "TXT",
    host: "@",
    status,
  });

  it("empty set → pending", () => {
    expect(rollupStatus([])).toBe("pending");
  });

  it("any failed dominates", () => {
    expect(rollupStatus([rec("published"), rec("failed")])).toBe("failed");
  });

  it("all published → published", () => {
    expect(rollupStatus([rec("published"), rec("published")])).toBe("published");
  });

  it("all pending → pending", () => {
    expect(rollupStatus([rec("pending"), rec("pending")])).toBe("pending");
  });

  it("mixed published + pending → propagating", () => {
    expect(rollupStatus([rec("published"), rec("pending")])).toBe("propagating");
  });

  it("any propagating → propagating", () => {
    expect(rollupStatus([rec("published"), rec("propagating")])).toBe(
      "propagating",
    );
  });
});
