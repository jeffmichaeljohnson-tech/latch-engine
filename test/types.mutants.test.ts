// Mutation-closing test for src/types.ts (LatchError).
import { describe, expect, it } from "vitest";
import { LatchError } from "../src/types";

describe("LatchError", () => {
  it("sets .name to 'LatchError' (so it is distinguishable in logs/instanceof reporting)", () => {
    // Prevents blanking `this.name = "LatchError"`.
    const err = new LatchError("internal", "boom");
    expect(err.name).toBe("LatchError");
    expect(err.code).toBe("internal");
    expect(err.message).toBe("boom");
  });
});
