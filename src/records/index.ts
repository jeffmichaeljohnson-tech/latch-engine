// Latch — email-DNS intelligence barrel.
//
// SPF/DKIM/DMARC/MX generation + merge + clobber-guards + apex handling +
// variable resolution. Pure, portable (Worker + Node), zero runtime deps.

export * from "./vars";
export * from "./spf";
export * from "./dkim";
export * from "./dmarc";
export * from "./mx";
export * from "./apex";
