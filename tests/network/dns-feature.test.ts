import { afterEach, describe, expect, it, vi } from "vitest";
import { handleDnsRequest } from "../../worker/api/dns.ts";
import { runDnsLeakTest } from "../../src/features/dns.ts";

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
});
const env = {
  DNS_SERVICE_URL: "https://dns-service.example",
  DNS_SERVICE_SECRET: "server-only-key-".repeat(3),
};
const id = "a".repeat(32);
const secret = "s".repeat(43);
const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
const session = () => ({
  id,
  secret,
  expiresAt: new Date(Date.now() + 150_000).toISOString(),
  probeUrls: [1, 2, 3, 4].map(
    (number) =>
      `https://q${number.toString().padStart(32, "0")}.probe.example.com/probe`,
  ),
});
const observation = () => ({
  id,
  expiresAt: new Date(Date.now() + 150_000).toISOString(),
  resolvers: [
    {
      ip: "2606:4700:0:0:0:0:0:1111",
      firstObservedAt: new Date().toISOString(),
      lastObservedAt: new Date().toISOString(),
      types: ["A", "AAAA"],
    },
  ],
  verdict: "unsafe-untrusted-upstream-conclusion",
});
function request(path: string, body: unknown = {}) {
  return new Request(`https://site.example${path}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Origin: "https://site.example",
    },
    body: JSON.stringify(body),
  });
}

describe("DNS Worker proxy (Mock upstream, no public network)", () => {
  it("stays unavailable without explicit valid configuration and never calls a default provider", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    for (const config of [
      {},
      { ...env, DNS_SERVICE_URL: "http://public.example" },
      { ...env, DNS_SERVICE_URL: "https://service.example/?endpoint=evil" },
    ]) {
      const response = await handleDnsRequest(
        request("/api/dns/start"),
        config,
      );
      expect(response.status).toBe(503);
      expect(response.headers.get("cache-control")).toBe("no-store");
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });
  it("validates method, input size, origin, credentials and client endpoint injection", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    expect(
      (
        await handleDnsRequest(
          new Request("https://site.example/api/dns/start"),
          env,
        )
      ).status,
    ).toBe(405);
    expect(
      (
        await handleDnsRequest(
          request("/api/dns/start", { endpoint: "https://attacker.example" }),
          env,
        )
      ).status,
    ).toBe(400);
    expect(
      (
        await handleDnsRequest(
          request("/api/dns/results", { id, secret: "wrong" }),
          env,
        )
      ).status,
    ).toBe(400);
    expect(
      (
        await handleDnsRequest(
          request("/api/dns/start", { x: "x".repeat(1024) }),
          env,
        )
      ).status,
    ).toBe(413);
    const cross = new Request("https://site.example/api/dns/start", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Origin: "https://attacker.example",
      },
      body: "{}",
    });
    expect((await handleDnsRequest(cross, env)).status).toBe(403);
    expect(fetchMock).not.toHaveBeenCalled();
  });
  it("forwards only to fixed configured routes, keeps service key private and sanitizes conclusions", async () => {
    const fetchMock = vi
      .fn()
      .mockImplementation((url: URL) =>
        Promise.resolve(
          jsonResponse(
            url.pathname.endsWith("/session")
              ? { ...session(), privateServiceKey: env.DNS_SERVICE_SECRET }
              : observation(),
          ),
        ),
      );
    vi.stubGlobal("fetch", fetchMock);
    const response = await handleDnsRequest(request("/api/dns/start"), env);
    expect(response.status).toBe(201);
    const body = await response.text();
    expect(body).not.toContain(env.DNS_SERVICE_SECRET);
    expect(body).toContain(secret);
    expect(fetchMock.mock.calls[0][0].href).toBe(
      "https://dns-service.example/v1/session",
    );
    expect(fetchMock.mock.calls[0][1].headers.Authorization).toBe(
      `Bearer ${env.DNS_SERVICE_SECRET}`,
    );
    const results = await (
      await handleDnsRequest(request("/api/dns/results", { id, secret }), env)
    ).json();
    expect(results.verdict).toBe("undetermined");
    expect(results.resolvers[0].ip).toBe("2606:4700::1111");
    expect(results).not.toHaveProperty("privateServiceKey");
  });
  it("accepts explicitly configured localhost HTTP and refuses unsafe probe URLs or malformed upstream", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse({
            ...session(),
            probeUrls: ["http://attacker.example/probe"],
          }),
        ),
    );
    expect(
      (
        await handleDnsRequest(request("/api/dns/start"), {
          ...env,
          DNS_SERVICE_URL: "http://127.0.0.1:8789",
        })
      ).status,
    ).toBe(502);
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockRejectedValue(new Error("Private upstream error with secrets")),
    );
    const result = await handleDnsRequest(request("/api/dns/start"), env);
    expect(result.status).toBe(503);
    expect(await result.text()).not.toContain("secrets");
  });
});

describe("DNS browser lifecycle (Mock fetch/authority, not real recursive DNS)", () => {
  it("does not probe when undeployed and does not persist credentials", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(
        jsonResponse({ error: "DNS_SERVICE_UNAVAILABLE" }, 503),
      );
    vi.stubGlobal("fetch", fetchMock);
    const result = await runDnsLeakTest();
    expect(result.status).toBe("unavailable");
    expect(result.resolvers).toEqual([]);
    expect(result.probeCount).toBe(0);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
  it("triggers real-shaped HTTPS requests, polls actual-shaped evidence and deletes session", async () => {
    vi.useFakeTimers();
    const fetchMock = vi
      .fn()
      .mockImplementation((input: string, init: RequestInit) => {
        if (input === "/api/dns/start")
          return Promise.resolve(jsonResponse(session(), 201));
        if (input === "/api/dns/results")
          return Promise.resolve(jsonResponse(observation()));
        if (input === "/api/dns/delete")
          return Promise.resolve(jsonResponse({ deleted: true }));
        expect(input.startsWith("https://q")).toBe(true);
        expect(init.credentials).toBe("omit");
        expect(init.mode).toBe("no-cors");
        return Promise.resolve({ type: "opaque" });
      });
    vi.stubGlobal("fetch", fetchMock);
    const onProgress = vi.fn();
    const pending = runDnsLeakTest({ onProgress });
    await vi.advanceTimersByTimeAsync(750);
    const result = await pending;
    expect(result.status).toBe("complete");
    expect(result.verdict).toBe("undetermined");
    expect(result.resolvers[0].ip).toBe("2606:4700::1111");
    expect(result.probeCount).toBe(4);
    expect(result.cleanupConfirmed).toBe(true);
    expect(
      fetchMock.mock.calls.filter(([url]) =>
        String(url).startsWith("https://q"),
      ),
    ).toHaveLength(4);
    expect(fetchMock.mock.calls.at(-1)?.[0]).toBe("/api/dns/delete");
    expect(onProgress.mock.calls.at(-1)?.[0].phase).toBe("finished");
    expect(vi.getTimerCount()).toBe(0);
    for (const [url, init] of fetchMock.mock.calls) {
      expect(String(url)).not.toContain(secret);
      if (url === "/api/dns/delete")
        expect(JSON.parse(init.body as string)).toEqual({ id, secret });
    }
  });
  it("does not treat opaque HTTP completion as resolver evidence", async () => {
    vi.useFakeTimers();
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockImplementation((url: string) =>
          Promise.resolve(
            url === "/api/dns/start"
              ? jsonResponse(session())
              : url === "/api/dns/results"
                ? jsonResponse({ ...observation(), resolvers: [] })
                : url === "/api/dns/delete"
                  ? jsonResponse({ deleted: true })
                  : { type: "opaque" },
          ),
        ),
    );
    const pending = runDnsLeakTest();
    await vi.advanceTimersByTimeAsync(3000);
    const result = await pending;
    expect(result.status).toBe("inconclusive");
    expect(result.resolvers).toEqual([]);
    expect(result.cleanupConfirmed).toBe(true);
    expect(vi.getTimerCount()).toBe(0);
  });
  it("deletes the session even when the caller aborts probe requests", async () => {
    const controller = new AbortController();
    const fetchMock = vi.fn().mockImplementation((url: string) => {
      if (url === "/api/dns/start")
        return Promise.resolve(jsonResponse(session()));
      if (url === "/api/dns/delete")
        return Promise.resolve(jsonResponse({ deleted: true }));
      if (url.startsWith("https://q")) {
        controller.abort();
        return Promise.reject(new Error("Cancelled"));
      }
      throw new Error("Polling after abort is forbidden");
    });
    vi.stubGlobal("fetch", fetchMock);
    const result = await runDnsLeakTest({ signal: controller.signal });
    expect(result.status).toBe("cancelled");
    expect(result.cleanupConfirmed).toBe(true);
    expect(fetchMock.mock.calls.at(-1)?.[0]).toBe("/api/dns/delete");
    expect(fetchMock.mock.calls.at(-1)?.[1].signal).not.toBe(controller.signal);
    // The independent cleanup request completes despite the caller's abort;
    // its own signal is then aborted to release any unread response resources.
    expect(fetchMock.mock.calls.at(-1)?.[1].signal.aborted).toBe(true);
  });
  it("rejects unsafe sessions and reports unconfirmed deletion honestly", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          jsonResponse({
            ...session(),
            probeUrls: ["https://attacker.example/probe"],
          }),
        ),
    );
    expect((await runDnsLeakTest()).status).toBe("error");
    const controller = new AbortController();
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation((url: string) => {
        if (url === "/api/dns/start")
          return Promise.resolve(jsonResponse(session()));
        if (url === "/api/dns/delete")
          return Promise.reject(new Error("Unavailable"));
        controller.abort();
        return Promise.reject(new Error("Cancelled"));
      }),
    );
    const result = await runDnsLeakTest({ signal: controller.signal });
    expect(result.cleanupConfirmed).toBe(false);
    expect(result.message).toContain("180");
  });
});
