import { afterEach, describe, expect, it, vi } from "vitest";
import {
  checkConnectivityTarget,
  checkRoutingNodes,
  runConnectivityChecks,
  checkPublicCorsEgress,
} from "../../src/features/connectivity";
import {
  isPublicCandidateAddress,
  parseIceCandidate,
  runWebRtcCheck,
} from "../../src/features/webrtc";
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
});
describe("browser connectivity with explicit synthetic browser responses", () => {
  it("does not contact sites without consent or invent routing when nodes are absent", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    await expect(runConnectivityChecks({ consent: false })).rejects.toThrow(
      "consent",
    );
    expect(await checkRoutingNodes([], { consent: true })).toMatchObject({
      status: "not-deployed",
      distinctExitIps: [],
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });
  it("describes an opaque fetch honestly and never claims a site exit IP", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ type: "opaque" }));
    const result = await checkConnectivityTarget(
      {
        id: "test",
        name: "test",
        url: "https://example.com/",
        method: "fetch-no-cors",
      },
      { consent: true },
    );
    expect(result.status).toBe("opaque-response");
    expect(result.exitIp).toBeNull();
    expect(result.message).toContain("无法确认");
  });
  it("cleans image handlers when aborted and treats image failure as inconclusive", async () => {
    let instance: {
      onload: (() => void) | null;
      onerror: (() => void) | null;
      removeAttribute: ReturnType<typeof vi.fn>;
      src: string;
    };
    class ImageMock {
      onload = null;
      onerror = null;
      removeAttribute = vi.fn();
      src = "";
      constructor() {
        instance = this;
      }
    }
    vi.stubGlobal("Image", ImageMock);
    const controller = new AbortController();
    const result = checkConnectivityTarget("github", {
      consent: true,
      signal: controller.signal,
    });
    controller.abort();
    expect((await result).status).toBe("cancelled");
    expect(instance!.onload).toBeNull();
    expect(instance!.removeAttribute).toHaveBeenCalledWith("src");
    const failure = checkConnectivityTarget("github", { consent: true });
    instance!.onerror!();
    expect((await failure).status).toBe("inconclusive");
  });
  it("only accepts readable real echo addresses and verifies configured address family", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          new Response(JSON.stringify({ ip: "2001:db8::1" }), {
            headers: { "Content-Type": "application/json" },
          }),
        ),
    );
    const result = await checkRoutingNodes(
      [{ id: "v4", name: "v4", url: "https://node.example/echo", family: 4 }],
      { consent: true },
    );
    expect(result.results[0].status).toBe("inconclusive");
    expect(result.distinctExitIps).toEqual([]);
  });
  it("canonicalizes equivalent IPv6 exits before comparing nodes", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockImplementation((url: URL) =>
          Promise.resolve(
            new Response(
              JSON.stringify({
                ip: url.hostname.startsWith("a.")
                  ? "2606:4700:0:0:0:0:0:1111"
                  : "2606:4700::1111",
              }),
              { headers: { "Content-Type": "application/json" } },
            ),
          ),
        ),
    );
    const result = await checkRoutingNodes(
      [
        { id: "a", name: "a", url: "https://a.example/echo" },
        { id: "b", name: "b", url: "https://b.example/echo" },
      ],
      { consent: true },
    );
    expect(result.distinctExitIps).toEqual(["2606:4700::1111"]);
  });
  it("stops oversized streaming echo responses before reading them into memory", async () => {
    const cancelled = vi.fn();
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array(4097));
      },
      cancel: cancelled,
    });
    const fetchMock = vi
      .fn()
      .mockResolvedValue(
        new Response(stream, {
          headers: { "Content-Type": "application/json" },
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    const result = await checkRoutingNodes(
      [{ id: "node", name: "node", url: "https://node.example/echo" }],
      { consent: true },
    );
    expect(result.results[0].status).toBe("inconclusive");
    expect(cancelled).toHaveBeenCalledOnce();
    expect(fetchMock.mock.calls[0][1].signal.aborted).toBe(true);
    const adapterFetch = vi
      .fn()
      .mockResolvedValue(
        new Response("x".repeat(4097), {
          headers: { "Content-Type": "application/json" },
        }),
      );
    vi.stubGlobal("fetch", adapterFetch);
    const parse = vi.fn();
    expect(
      await checkPublicCorsEgress(
        {
          id: "test",
          targetId: "test",
          endpoint: "https://approved.example/echo",
          authorizedForPublicUse: true,
          parse,
        },
        { consent: true },
      ),
    ).toBeNull();
    expect(parse).not.toHaveBeenCalled();
  });
  it("refuses endpoint query credentials and aborts unread opaque response resources", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ type: "opaque" });
    vi.stubGlobal("fetch", fetchMock);
    const result = await checkRoutingNodes(
      [
        {
          id: "node",
          name: "node",
          url: "https://node.example/echo?privateKey=secret",
        },
      ],
      { consent: true },
    );
    expect(result.results[0].status).toBe("inconclusive");
    expect(fetchMock).not.toHaveBeenCalled();
    await checkConnectivityTarget(
      {
        id: "opaque",
        name: "opaque",
        url: "https://example.com/",
        method: "fetch-no-cors",
      },
      { consent: true },
    );
    expect(fetchMock.mock.calls[0][1].signal.aborted).toBe(true);
  });
});

describe("WebRTC logic and cleanup with a synthetic peer implementation", () => {
  it("recognizes mDNS/private/public addresses without assigning abuse", () => {
    expect(isPublicCandidateAddress("192.168.1.2")).toBe(false);
    expect(isPublicCandidateAddress("100.64.1.1")).toBe(false);
    expect(isPublicCandidateAddress("2001:db8::1")).toBe(false);
    expect(isPublicCandidateAddress("2606:4700::1111")).toBe(true);
    expect(isPublicCandidateAddress("3fff::1")).toBe(false);
    expect(isPublicCandidateAddress("2002::1")).toBe(false);
    expect(isPublicCandidateAddress("192.88.99.1")).toBe(false);
    const candidate = parseIceCandidate({
      candidate: "candidate:1 1 UDP 1 abc.local 1234 typ host",
      address: null,
      type: null,
      protocol: null,
      port: null,
    });
    expect(candidate.mdns).toBe(true);
    expect(candidate.type).toBe("host");
    expect(candidate.isPublic).toBe(false);
  });
  it("runs without external ICE servers or media permissions and cleans resources after gathering", async () => {
    let instance: PeerMock;
    const channelClose = vi.fn();
    class PeerMock {
      onicecandidate: ((event: { candidate: null }) => void) | null = null;
      onicegatheringstatechange = null;
      onicecandidateerror = null;
      close = vi.fn();
      createDataChannel = () => ({ close: channelClose });
      constructor(public configuration: RTCConfiguration) {
        instance = this;
      }
      createOffer = async () => ({});
      setLocalDescription = async () => {
        queueMicrotask(() => this.onicecandidate?.({ candidate: null }));
      };
    }
    vi.stubGlobal("RTCPeerConnection", PeerMock);
    const result = await runWebRtcCheck();
    expect(instance!.configuration.iceServers).toEqual([]);
    expect(result.status).toBe("limited");
    expect(instance!.close).toHaveBeenCalledOnce();
    expect(channelClose).toHaveBeenCalledOnce();
    expect(instance!.onicecandidate).toBeNull();
  });
  it("cleans connections after cancellation and reports unavailable support", async () => {
    const close = vi.fn();
    const channelClose = vi.fn();
    class PeerMock {
      close = close;
      createDataChannel = () => ({ close: channelClose });
      createOffer = () => new Promise(() => {});
    }
    vi.stubGlobal("RTCPeerConnection", PeerMock);
    const controller = new AbortController();
    const pending = runWebRtcCheck({ signal: controller.signal });
    controller.abort();
    expect((await pending).status).toBe("cancelled");
    expect(close).toHaveBeenCalledOnce();
    expect(channelClose).toHaveBeenCalledOnce();
    vi.stubGlobal("RTCPeerConnection", undefined);
    expect((await runWebRtcCheck()).status).toBe("unsupported");
  });
  it("closes timed-out connections and failures without reporting successful privacy", async () => {
    vi.useFakeTimers();
    const close = vi.fn();
    const channelClose = vi.fn();
    class PeerMock {
      close = close;
      createDataChannel = () => ({ close: channelClose });
      createOffer = () => new Promise(() => {});
    }
    vi.stubGlobal("RTCPeerConnection", PeerMock);
    const pending = runWebRtcCheck({ timeoutMs: 500 });
    await vi.advanceTimersByTimeAsync(500);
    expect((await pending).status).toBe("limited");
    expect(close).toHaveBeenCalledOnce();
    expect(channelClose).toHaveBeenCalledOnce();
    expect(vi.getTimerCount()).toBe(0);
    vi.stubGlobal(
      "RTCPeerConnection",
      class {
        constructor() {
          throw new Error("Browser disabled");
        }
      },
    );
    expect((await runWebRtcCheck()).status).toBe("error");
    expect(vi.getTimerCount()).toBe(0);
  });
  it("does not equate configured STUN with a successful srflx observation or relay IP with visitor exposure", async () => {
    let candidateType = "relay";
    class PeerMock {
      onicecandidate: ((event: { candidate: unknown }) => void) | null = null;
      close = vi.fn();
      createDataChannel = () => ({ close: vi.fn() });
      createOffer = async () => ({});
      setLocalDescription = async () => {
        this.onicecandidate?.({
          candidate: {
            candidate: `candidate:1 1 UDP 1 8.8.8.8 1234 typ ${candidateType}`,
            address: "8.8.8.8",
            type: candidateType,
            protocol: "udp",
            port: 1234,
          },
        });
        this.onicecandidate?.({ candidate: null });
      };
    }
    vi.stubGlobal("RTCPeerConnection", PeerMock);
    const relay = await runWebRtcCheck({
      httpIp: "1.1.1.1",
      iceServers: [{ urls: "stun:owned.example" }],
    });
    expect(relay.status).toBe("limited");
    expect(relay.publicIps).toEqual([]);
    expect(relay.differentPublicIps).toEqual([]);
    candidateType = "srflx";
    const srflx = await runWebRtcCheck({
      httpIp: "1.1.1.1",
      iceServers: [{ urls: "stun:owned.example" }],
    });
    expect(srflx.status).toBe("complete");
    expect(srflx.differentPublicIps).toEqual(["8.8.8.8"]);
  });
});
