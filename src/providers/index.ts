// Latch — providers barrel.
//
// Adapter registry + the four write adapters (Cloudflare, Domain Connect sync,
// Namecheap, Route 53) behind the single Adapter interface from ../types.

export {
  registerAdapter,
  getAdapter,
  listAdapters,
} from "./registry";

export {
  CloudflareAdapter,
  cloudflareAdapter,
  CLOUDFLARE_CAPABILITIES,
  readBack,
  type CfDnsRecord,
} from "./cloudflare";

export {
  DomainConnectAdapter,
  domainConnectAdapter,
  makeDomainConnectAdapter,
  type DomainConnectConfig,
} from "./domain-connect";

export {
  NamecheapAdapter,
  namecheapAdapter,
  NAMECHEAP_CAPABILITIES,
  unionHosts,
} from "./namecheap";

export {
  Route53Adapter,
  route53Adapter,
  ROUTE53_CAPABILITIES,
  buildChangeBatchXml,
} from "./route53";

export { signRequest, type SigV4Input, type SigV4Result } from "./sigv4";

export {
  validateManifest,
  manifestAdapter,
  registerManifestAdapter,
  KNOWN_PLACEHOLDERS,
  type AdapterManifest,
  type ManifestAdapter,
  type ManifestAdapterOptions,
  type ManifestCapabilities,
  type ManifestCreate,
  type ManifestRead,
  type ManifestRecordMap,
  type ManifestRequest,
  type BodyTemplate,
  type ValidateResult,
} from "./manifest";
