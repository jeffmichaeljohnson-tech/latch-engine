// Latch engine — public surface.
//
// Barrel for the portable (Worker + Node), zero-runtime-dependency DNS engine.
// Consumers import from here; internal modules import their siblings directly.

export * from "./types";

// Lanes append their exports below as they land:
//   export * from "./records";   // email-DNS intelligence (SPF/DKIM/DMARC/MX)
//   export * from "./detect";    // provider detection + Domain Connect discovery
//   export * from "./providers"; // adapter registry + implementations
//   export * from "./verify";    // DoH poller + two-tier status
