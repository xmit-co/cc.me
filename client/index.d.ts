interface CapturedHeader {
  name: string;
  value: string;
  valueBytes: Uint8Array;
}

interface CapturedRequest {
  id: string;
  received_at_unix_ms: number;
  method: string;
  path: string;
  query: string | null;
  headers: CapturedHeader[];
  bodyBytes: Uint8Array;
  text(): string;
  json(): unknown;
}

interface DeliveryEnvelope {
  id: string;
  sealed: string;
}

interface DeliveryResponse {
  count: number;
  items: DeliveryEnvelope[];
  cursor?: string | null;
}

interface DecryptedDeliveryResponse extends DeliveryResponse {
  requests: CapturedRequest[];
}

interface AckResponse {
  acked: number;
  missing: string[];
}

interface ReleaseResponse {
  released: number;
  missing: string[];
}

interface UrlOptions {
  baseUrl?: string;
  params?: URLSearchParams | Record<string, string | number | boolean | null | undefined>;
}

interface FetchOptions {
  baseUrl?: string;
  fetch?: typeof fetch;
  headers?: HeadersInit;
  signal?: AbortSignal;
}

interface AliasResponse {
  url: string;
}

interface InboxUrlOptions {
  baseUrl?: string;
  limit?: number;
  poll?: boolean;
  cursor?: string;
}

interface ClientOptions {
  baseUrl?: string;
  privateKey: string | Uint8Array;
  fetch?: typeof fetch;
}

interface DeliveryOptions {
  limit?: number;
  poll?: boolean;
  cursor?: string;
  decrypt?: boolean;
  headers?: HeadersInit;
  signal?: AbortSignal;
}

interface BatchOptions {
  headers?: HeadersInit;
  signal?: AbortSignal;
}

export function privateKey(file?: string | URL): Promise<string>;
export function trampolineUrl(target: string | URL, options?: UrlOptions): string;
export function createAlias(target: string | URL, options?: FetchOptions): Promise<AliasResponse>;

export class CcMeClient {
  constructor(options: ClientOptions);
  inboxUrl(options?: InboxUrlOptions): Promise<string>;
  webmentionUrl(): Promise<string>;
  websubUrl(): Promise<string>;
  slackUrl(): Promise<string>;
  pingbackUrl(): Promise<string>;
  metaUrl(verifyToken?: string): Promise<string>;
  cloudEventsUrl(): Promise<string>;
  discordUrl(discordPublicKey: string): Promise<string>;
  peek(options?: DeliveryOptions & { decrypt: false }): Promise<DeliveryResponse>;
  peek(options?: DeliveryOptions): Promise<DecryptedDeliveryResponse>;
  claim(options?: DeliveryOptions & { decrypt: false }): Promise<DeliveryResponse>;
  claim(options?: DeliveryOptions): Promise<DecryptedDeliveryResponse>;
  ack(idOrIds: string | string[], options?: BatchOptions): Promise<AckResponse>;
  release(idOrIds: string | string[], options?: BatchOptions): Promise<ReleaseResponse>;
}

export default CcMeClient;
