// Latch — detection lane public surface.

export { detect, type DetectOptions } from "./detect";
export {
  matchNameservers,
  normalizeNs,
  type ProviderIdentity,
  type ProviderTreatment,
} from "./ns-map";
export {
  discoverDomainConnect,
  settingsUrl,
  type DomainConnectSettings,
  type DomainConnectResult,
  type SettingsFetcher,
} from "./domain-connect";
