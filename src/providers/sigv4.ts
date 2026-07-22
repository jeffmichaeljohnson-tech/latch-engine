// Latch — AWS Signature Version 4 signer.
//
// Deterministic request signing for the Route 53 adapter. Uses Web Crypto
// (crypto.subtle HMAC-SHA256 + SHA-256 digest) so it runs unchanged in a
// Cloudflare Worker and in Node — zero runtime dependencies.
//
// Security-sensitive: this is the whole trust boundary for a Route 53 write.
// It is verified against the public AWS "aws-sig-v4-test-suite" get-vanilla
// known-answer vector (see test/providers/route53.test.ts). Do not "simplify"
// the canonicalization steps — each one is load-bearing for a valid signature.
//
// References: AWS SigV4 signing process
//   https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html

const ALGORITHM = "AWS4-HMAC-SHA256";
const encoder = new TextEncoder();

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

async function sha256Hex(message: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(message));
  return toHex(new Uint8Array(digest));
}

async function hmac(key: Uint8Array, message: string): Promise<Uint8Array> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    key as unknown as ArrayBuffer,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", cryptoKey, encoder.encode(message));
  return new Uint8Array(sig);
}

/**
 * RFC 3986 percent-encoding used for the canonical query string. Unreserved
 * characters (A-Z a-z 0-9 - _ . ~) pass through; everything else is encoded.
 */
function encodeRfc3986(value: string): string {
  return encodeURIComponent(value).replace(
    /[!'()*]/g,
    (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase(),
  );
}

/** Encode a URI path, preserving the "/" separators between segments. */
function encodeCanonicalUri(path: string): string {
  if (path === "" || path === "/") return "/";
  return path
    .split("/")
    .map((segment) => encodeRfc3986(segment))
    .join("/");
}

function canonicalQueryString(search: string): string {
  if (!search || search === "?") return "";
  const params = new URLSearchParams(search);
  const pairs: [string, string][] = [];
  for (const [k, v] of params) pairs.push([k, v]);
  pairs.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : 1));
  return pairs.map(([k, v]) => `${encodeRfc3986(k)}=${encodeRfc3986(v)}`).join("&");
}

export interface SigV4Input {
  method: string;
  /** Full request URL (scheme://host/path?query). */
  url: string;
  region: string;
  service: string;
  accessKeyId: string;
  secretAccessKey: string;
  /** For temporary (STS) credentials — signed as x-amz-security-token. */
  sessionToken?: string;
  /** Request body; defaults to the empty string (GET). */
  body?: string;
  /**
   * Extra headers to include in the signature. `host` is derived from `url`
   * automatically. Provide `x-amz-date` here, or let it default to now.
   */
  headers?: Record<string, string>;
  /** Override the timestamp for deterministic tests (YYYYMMDDTHHMMSSZ). */
  amzDate?: string;
}

export interface SigV4Result {
  authorization: string;
  amzDate: string;
  signedHeaders: string;
  signature: string;
  /** Full header set to send with the request (includes Authorization). */
  headers: Record<string, string>;
}

function nowAmzDate(): string {
  // 2015-08-30T12:36:00.000Z -> 20150830T123600Z
  return new Date().toISOString().replace(/[:-]/g, "").replace(/\.\d{3}Z$/, "Z");
}

/**
 * Sign a request with AWS SigV4. Returns the Authorization header (and the
 * full header set to send). Only the headers passed in `headers` plus the
 * derived `host` are signed — keep unsigned headers (e.g. Content-Type) out
 * of `headers` if they must not participate in the signature.
 */
export async function signRequest(input: SigV4Input): Promise<SigV4Result> {
  const { method, url, region, service, accessKeyId, secretAccessKey } = input;
  const body = input.body ?? "";
  const amzDate = input.amzDate ?? nowAmzDate();
  const dateStamp = amzDate.slice(0, 8);

  const parsed = new URL(url);

  // Assemble the header set to sign: caller headers + derived host.
  const headerMap = new Map<string, string>();
  for (const [k, v] of Object.entries(input.headers ?? {})) {
    headerMap.set(k.toLowerCase(), v.trim().replace(/\s+/g, " "));
  }
  headerMap.set("host", parsed.host);
  if (!headerMap.has("x-amz-date")) headerMap.set("x-amz-date", amzDate);
  if (input.sessionToken) headerMap.set("x-amz-security-token", input.sessionToken);

  const sortedHeaderNames = [...headerMap.keys()].sort();
  const canonicalHeaders = sortedHeaderNames
    .map((name) => `${name}:${headerMap.get(name)}\n`)
    .join("");
  const signedHeaders = sortedHeaderNames.join(";");

  const payloadHash = await sha256Hex(body);

  const canonicalRequest = [
    method.toUpperCase(),
    encodeCanonicalUri(parsed.pathname),
    canonicalQueryString(parsed.search),
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    ALGORITHM,
    amzDate,
    credentialScope,
    await sha256Hex(canonicalRequest),
  ].join("\n");

  // Derive the signing key: HMAC chain rooted at "AWS4" + secret.
  const kDate = await hmac(encoder.encode(`AWS4${secretAccessKey}`), dateStamp);
  const kRegion = await hmac(kDate, region);
  const kService = await hmac(kRegion, service);
  const kSigning = await hmac(kService, "aws4_request");
  const signature = toHex(await hmac(kSigning, stringToSign));

  const authorization =
    `${ALGORITHM} Credential=${accessKeyId}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const headers: Record<string, string> = {};
  for (const name of sortedHeaderNames) headers[name] = headerMap.get(name) as string;
  headers["authorization"] = authorization;

  return { authorization, amzDate, signedHeaders, signature, headers };
}
