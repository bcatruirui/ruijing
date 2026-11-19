import { parseIp } from "../../shared/ip.ts";
export interface IceCandidateInfo {
  type: "host" | "srflx" | "prflx" | "relay" | "unknown";
  address: string | null;
  protocol: string | null;
  port: number | null;
  mdns: boolean;
  isPublic: boolean;
}
export interface WebRtcResult {
  status: "complete" | "limited" | "unsupported" | "error" | "cancelled";
  supported: boolean;
  candidates: IceCandidateInfo[];
  mdnsDetected: boolean;
  publicIps: string[];
  differentPublicIps: string[];
  stunConfigured: boolean;
  message: string;
  checkedAt: string;
}
export interface WebRtcOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
  httpIp?: string;
  iceServers?: RTCIceServer[];
}

export function isPublicCandidateAddress(address: string | null): boolean {
  return parseIp(address)?.isPublic ?? false;
}

export function parseIceCandidate(
  candidate: Pick<
    RTCIceCandidate,
    "candidate" | "type" | "address" | "protocol" | "port"
  >,
): IceCandidateInfo {
  const words = candidate.candidate.trim().split(/\s+/);
  const typeIndex = words.indexOf("typ");
  const rawType =
    candidate.type ?? (typeIndex >= 0 ? words[typeIndex + 1] : "unknown");
  const type = ["host", "srflx", "prflx", "relay"].includes(rawType ?? "")
    ? (rawType as IceCandidateInfo["type"])
    : "unknown";
  const address = candidate.address || words[4] || null;
  const port =
    candidate.port ??
    (Number.isInteger(Number(words[5])) ? Number(words[5]) : null);
  return {
    type,
    address,
    protocol: candidate.protocol || words[2]?.toLowerCase() || null,
    port,
    mdns: Boolean(address?.toLowerCase().endsWith(".local")),
    isPublic: isPublicCandidateAddress(address),
  };
}

/** No media permissions, external STUN, upload, persistence, or signaling are used by default. */
export async function runWebRtcCheck(
  options: WebRtcOptions = {},
): Promise<WebRtcResult> {
  const base = {
    supported: typeof globalThis.RTCPeerConnection === "function",
    candidates: [] as IceCandidateInfo[],
    mdnsDetected: false,
    publicIps: [] as string[],
    differentPublicIps: [] as string[],
    stunConfigured: Boolean(options.iceServers?.length),
    checkedAt: new Date().toISOString(),
  };
  if (!base.supported)
    return {
      ...base,
      status: "unsupported",
      message: "浏览器不支持 WebRTC；无法检测。 / WebRTC is unavailable.",
    };
  if (options.signal?.aborted)
    return { ...base, status: "cancelled", message: "检测已取消 / Cancelled." };
  return new Promise((resolve) => {
    let pc: RTCPeerConnection | undefined;
    let channel: RTCDataChannel | undefined;
    let finished = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const candidates: IceCandidateInfo[] = [];
    const finish = (state: "gathered" | "timeout" | "error" | "cancelled") => {
      if (finished) return;
      finished = true;
      if (timer) clearTimeout(timer);
      options.signal?.removeEventListener("abort", cancel);
      if (pc) {
        pc.onicecandidate = null;
        pc.onicegatheringstatechange = null;
        pc.onicecandidateerror = null;
      }
      try {
        channel?.close();
      } catch {
        /* already closed */
      }
      try {
        pc?.close();
      } catch {
        /* already closed */
      }
      // A relay's address belongs to the TURN infrastructure, not necessarily
      // the visitor. Do not turn a normal relay into a claimed visitor IP leak.
      const publicIps = [
        ...new Set(
          candidates
            .filter(
              (item) => item.isPublic && item.address && item.type !== "relay",
            )
            .map((item) => parseIp(item.address)!.canonical),
        ),
      ];
      const normalize = (ip: string) => parseIp(ip)?.canonical ?? ip;
      const differentPublicIps = options.httpIp
        ? publicIps.filter((ip) => normalize(ip) !== normalize(options.httpIp!))
        : [];
      const hasServerReflexiveCandidate = candidates.some(
        (item) =>
          item.type === "srflx" && item.address && parseIp(item.address),
      );
      const status: WebRtcResult["status"] =
        state === "cancelled"
          ? "cancelled"
          : state === "error"
            ? "error"
            : state === "timeout" ||
                !base.stunConfigured ||
                !hasServerReflexiveCandidate
              ? "limited"
              : "complete";
      const message =
        state === "cancelled"
          ? "检测已取消，连接资源已关闭。 / Cancelled; connection resources closed."
          : state === "error"
            ? "WebRTC 初始化或候选收集失败，无法作出隐私结论。 / ICE gathering failed; no privacy conclusion is possible."
            : differentPublicIps.length
              ? "观察到与 HTTP 出口不同的公网候选，可能存在额外地址暴露；需要结合预期网络策略判断。 / Different public candidates observed; interpret against your intended network policy."
              : !base.stunConfigured
                ? "仅运行本地 ICE 检测，未配置自建 STUN；公网暴露检测能力受限，未发现候选不等于没有泄漏。 / Local ICE only; no self-hosted STUN is configured, so public exposure cannot be fully assessed."
                : state === "timeout"
                  ? "候选收集超时，检测能力受限；没有候选不代表不存在暴露。 / ICE gathering timed out; absence of candidates does not prove privacy."
                  : !hasServerReflexiveCandidate
                    ? "已配置 STUN，但未观察到服务端反射候选；可能受网络或浏览器策略限制，不能据此确认没有泄漏。 / STUN is configured but no server-reflexive candidate was observed; this does not establish absence of leaks."
                    : "候选收集完成；结果只描述本次可见候选，不能保证所有连接均无泄漏。 / ICE gathering completed; this does not guarantee that all traffic is private.";
      resolve({
        ...base,
        status,
        candidates,
        mdnsDetected: candidates.some((item) => item.mdns),
        publicIps,
        differentPublicIps,
        message,
      });
    };
    const cancel = () => finish("cancelled");
    options.signal?.addEventListener("abort", cancel, { once: true });
    timer = setTimeout(
      () => finish("timeout"),
      Math.min(20_000, Math.max(500, options.timeoutMs ?? 5_000)),
    );
    try {
      pc = new RTCPeerConnection({
        iceServers: options.iceServers ?? [],
        iceCandidatePoolSize: 0,
      });
      pc.onicecandidate = (event) => {
        if (!event.candidate) {
          finish("gathered");
          return;
        }
        if (candidates.length >= 64) return;
        const parsed = parseIceCandidate(event.candidate);
        if (
          !candidates.some(
            (item) =>
              item.type === parsed.type &&
              item.address === parsed.address &&
              item.port === parsed.port &&
              item.protocol === parsed.protocol,
          )
        )
          candidates.push(parsed);
      };
      pc.onicegatheringstatechange = () => {
        if (pc?.iceGatheringState === "complete") finish("gathered");
      };
      channel = pc.createDataChannel("ruijing-privacy-check");
      void pc
        .createOffer()
        .then((offer) => {
          if (!finished) return pc!.setLocalDescription(offer);
        })
        .catch(() => finish("error"));
    } catch {
      finish("error");
    }
  });
}
