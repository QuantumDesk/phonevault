// WalletConnect transport. The SDK (Reown WalletKit) only carries messages between the dApp and
// this app: it never sees a key and nothing here can sign. Requests are validated in Rust
// (`wc.rs`) and every signature comes from the phone through the existing verified commands.
//
// `createSdkBackend` loads the SDK lazily, so the main bundle stays small and the SDK is never
// loaded without a project ID. The browser preview uses `wc-mock.ts` behind the same interface.

export interface Meta { name: string; description?: string; url: string; icons: string[] }
export type Validation = "VALID" | "INVALID" | "UNKNOWN";
export interface VerifyIn { validation: Validation; origin: string; isScam: boolean }
export interface ProposalIn { id: number; meta: Meta; required: unknown; optional: unknown; verify: VerifyIn | null; expiry: number }
export interface Namespace { chains?: string[]; accounts: string[]; methods: string[]; events: string[] }
export interface SessionIn { topic: string; meta: Meta; namespaces: Record<string, Namespace>; expiry: number }
export interface RequestIn { id: number; topic: string; method: string; params: unknown; chainId: string; verify: VerifyIn | null; expiry: number | null }

export interface Events {
  proposal(p: ProposalIn): void;
  /** Something changed: new request queued, session list changed, relay state changed. */
  changed(): void;
  requestExpired(id: number): void;
  proposalExpired(id: number): void;
  sessionGone(topic: string, why: "deleted" | "expired"): void;
}

export interface Backend {
  pair(uri: string): Promise<void>;
  approve(id: number, namespaces: unknown): Promise<void>;
  reject(id: number): Promise<void>;
  respond(topic: string, id: number, result: unknown): Promise<void>;
  respondError(topic: string, id: number, code: number, message: string): Promise<void>;
  update(topic: string, namespaces: unknown): Promise<void>;
  emitChainChanged(topic: string, chainId: number): Promise<void>;
  disconnect(topic: string): Promise<void>;
  sessions(): SessionIn[];
  /** Every request the dApps sent that has not been answered yet, oldest first. */
  requests(): RequestIn[];
  isPending(id: number): boolean;
  online(): boolean;
  /** Last relay error, for explaining a connection that doesn't come up (e.g. a wrong project ID). */
  relayError(): string | null;
}

type AnyVerify = { verified?: { validation?: string; origin?: string; isScam?: boolean } } | undefined;
export function verifyOf(ctx: AnyVerify): VerifyIn | null {
  const v = ctx?.verified;
  if (!v) return null;
  const validation = (["VALID", "INVALID", "UNKNOWN"].includes(v.validation ?? "") ? v.validation : "UNKNOWN") as Validation;
  return { validation, origin: v.origin ?? "", isScam: v.isScam === true };
}

function meta(m: Partial<Meta> | undefined): Meta {
  return { name: String(m?.name ?? "Unknown dApp").slice(0, 80), description: m?.description ? String(m.description).slice(0, 300) : undefined, url: String(m?.url ?? ""), icons: Array.isArray(m?.icons) ? m!.icons.map(String) : [] };
}

export async function createSdkBackend(projectId: string, ev: Events): Promise<Backend> {
  const [{ Core }, { WalletKit }, { getSdkError }] = await Promise.all([
    import("@walletconnect/core"), import("@reown/walletkit"), import("@walletconnect/utils"),
  ]);
  // No telemetry: Core otherwise batches usage events to pulse.walletconnect.org.
  const core = new Core({ projectId, telemetryEnabled: false });
  // The flag stops event batching, but WalletKit still calls eventClient.init(), which posts an
  // INIT beacon (client id, user agent) regardless. Nothing here is sent: both entry points are no-ops.
  const ec = core.eventClient as unknown as { init: () => Promise<void>; sendEvent: (e: unknown) => Promise<{ ok: boolean }> };
  ec.init = async () => {};
  ec.sendEvent = async () => ({ ok: true });
  const kit = await WalletKit.init({
    core,
    metadata: {
      name: "Phone Vault",
      description: "Offline phone wallet. Every signature is reviewed and approved on the phone.",
      url: location.origin,
      icons: [],
    },
  });

  kit.on("session_proposal", (p) => {
    ev.proposal({
      id: p.id, meta: meta(p.params.proposer.metadata), required: p.params.requiredNamespaces ?? {},
      optional: p.params.optionalNamespaces ?? {}, verify: verifyOf(p.verifyContext), expiry: p.params.expiryTimestamp,
    });
  });
  kit.on("session_request", () => ev.changed());
  kit.on("session_delete", ({ topic }) => ev.sessionGone(topic, "deleted"));
  kit.on("proposal_expire", ({ id }) => ev.proposalExpired(id));
  kit.on("session_request_expire", ({ id }) => ev.requestExpired(id));
  // Not re-emitted by WalletKit; the sign client has them. Pings are answered by the SDK itself.
  kit.engine.signClient.events.on("session_expire", ({ topic }) => ev.sessionGone(topic, "expired"));
  kit.engine.signClient.events.on("session_ping", () => ev.changed());
  // The SDK emits `session_request` one at a time; queued ones only show in the pending store.
  core.relayer.on("relayer_message", () => setTimeout(() => ev.changed(), 50));
  let relayError: string | null = null;
  core.relayer.on("relayer_connect", () => { relayError = null; ev.changed(); });
  core.relayer.on("relayer_error", (e: unknown) => { relayError = String((e as { message?: string })?.message ?? e).slice(0, 200); ev.changed(); });
  core.relayer.on("relayer_disconnect", () => ev.changed());

  const toRequest = (r: ReturnType<typeof kit.getPendingSessionRequests>[number]): RequestIn => ({
    id: r.id, topic: r.topic, method: r.params.request.method, params: r.params.request.params, chainId: r.params.chainId,
    verify: verifyOf(r.verifyContext), expiry: r.params.request.expiryTimestamp ?? null,
  });

  return {
    pair: (uri) => kit.pair({ uri }),
    approve: async (id, namespaces) => { await kit.approveSession({ id, namespaces: namespaces as never }); },
    reject: (id) => kit.rejectSession({ id, reason: getSdkError("USER_REJECTED") }),
    respond: (topic, id, result) => kit.respondSessionRequest({ topic, response: { id, jsonrpc: "2.0", result } }),
    respondError: (topic, id, code, message) => kit.respondSessionRequest({ topic, response: { id, jsonrpc: "2.0", error: { code, message } } }),
    update: async (topic, namespaces) => { await kit.updateSession({ topic, namespaces: namespaces as never }); },
    emitChainChanged: (topic, chainId) => kit.emitSessionEvent({ topic, event: { name: "chainChanged", data: chainId }, chainId: `eip155:${chainId}` }),
    disconnect: (topic) => kit.disconnectSession({ topic, reason: getSdkError("USER_DISCONNECTED") }),
    sessions: () => Object.values(kit.getActiveSessions()).map((s) => ({ topic: s.topic, meta: meta(s.peer.metadata), namespaces: s.namespaces as Record<string, Namespace>, expiry: s.expiry })),
    requests: () => kit.getPendingSessionRequests().map(toRequest).sort((a, b) => a.id - b.id),
    isPending: (id) => kit.getPendingSessionRequests().some((r) => r.id === id),
    online: () => core.relayer.connected,
    relayError: () => relayError,
  };
}
