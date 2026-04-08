/**
 * AEGIS Live WebSocket client.
 *
 * Single persistent connection to /ws with:
 *   - Auto-reconnect (exponential backoff, max 30s)
 *   - Topic subscribe/unsubscribe API
 *   - Ping heartbeat every 25s
 *   - Multi-callback per topic
 *
 * Usage:
 *   const ws = getLiveWS();
 *   const off = ws.subscribe("incidents.new", (msg) => { ... });
 *   off(); // unsubscribe
 */

type Handler = (data: unknown) => void;

export interface WSMessage {
  type: string;
  topic?: string;
  data?: unknown;
  timestamp?: string;
  severity?: string;
}

export type WSStatus = "idle" | "connecting" | "open" | "closed" | "error";

class LiveWS {
  private ws: WebSocket | null = null;
  private url: string;
  private handlers = new Map<string, Set<Handler>>();
  private statusHandlers = new Set<(s: WSStatus) => void>();
  private status: WSStatus = "idle";
  private reconnectAttempt = 0;
  private reconnectTimer: number | null = null;
  private pingTimer: number | null = null;
  private closedByUser = false;
  private subscribedTopics = new Set<string>();

  constructor(url: string) {
    this.url = url;
  }

  private setStatus(s: WSStatus) {
    this.status = s;
    this.statusHandlers.forEach((h) => {
      try {
        h(s);
      } catch {
        /* noop */
      }
    });
  }

  getStatus(): WSStatus {
    return this.status;
  }

  onStatus(cb: (s: WSStatus) => void): () => void {
    this.statusHandlers.add(cb);
    cb(this.status);
    return () => this.statusHandlers.delete(cb);
  }

  connect() {
    if (typeof window === "undefined") return;
    if (this.ws && (this.ws.readyState === WebSocket.OPEN || this.ws.readyState === WebSocket.CONNECTING)) {
      return;
    }
    this.closedByUser = false;
    this.setStatus("connecting");

    try {
      this.ws = new WebSocket(this.url);
    } catch (err) {
      console.error("[ws] failed to construct WebSocket", err);
      this.setStatus("error");
      this.scheduleReconnect();
      return;
    }

    this.ws.onopen = () => {
      this.reconnectAttempt = 0;
      this.setStatus("open");
      // Re-subscribe to all topics via event_types filter
      if (this.subscribedTopics.size > 0) {
        this.sendRaw({
          type: "subscribe",
          event_types: Array.from(this.subscribedTopics),
        });
      }
      this.startPing();
    };

    this.ws.onmessage = (ev) => {
      let msg: WSMessage;
      try {
        msg = JSON.parse(ev.data);
      } catch {
        return;
      }
      if (msg.type === "pong" || msg.type === "filters_updated" || msg.type === "subscribed") {
        return;
      }
      // Dispatch by topic (msg.topic preferred; fallback to msg.type)
      const topic = (msg.topic || msg.type || "").toString();
      this.dispatch(topic, msg);
      // Wildcard "*" subscribers always receive
      this.dispatch("*", msg);
    };

    this.ws.onerror = () => {
      this.setStatus("error");
    };

    this.ws.onclose = () => {
      this.stopPing();
      this.setStatus("closed");
      this.ws = null;
      if (!this.closedByUser) {
        this.scheduleReconnect();
      }
    };
  }

  private dispatch(topic: string, msg: WSMessage) {
    const set = this.handlers.get(topic);
    if (!set || set.size === 0) return;
    // Most widgets want the inner payload
    const payload = (msg.data !== undefined ? msg.data : msg) as unknown;
    set.forEach((h) => {
      try {
        h(payload);
      } catch (err) {
        console.error(`[ws] handler error on topic ${topic}`, err);
      }
    });
  }

  private scheduleReconnect() {
    if (this.reconnectTimer !== null) return;
    const delay = Math.min(30_000, 500 * Math.pow(2, this.reconnectAttempt));
    this.reconnectAttempt += 1;
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }

  private startPing() {
    this.stopPing();
    this.pingTimer = window.setInterval(() => {
      this.sendRaw({ type: "ping" });
    }, 25_000);
  }

  private stopPing() {
    if (this.pingTimer !== null) {
      window.clearInterval(this.pingTimer);
      this.pingTimer = null;
    }
  }

  private sendRaw(obj: Record<string, unknown>) {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) return;
    try {
      this.ws.send(JSON.stringify(obj));
    } catch (err) {
      console.error("[ws] send failed", err);
    }
  }

  /**
   * Subscribe a handler to a topic. Returns an unsubscribe function.
   */
  subscribe(topic: string, handler: Handler): () => void {
    let set = this.handlers.get(topic);
    if (!set) {
      set = new Set();
      this.handlers.set(topic, set);
    }
    set.add(handler);

    if (topic !== "*" && !this.subscribedTopics.has(topic)) {
      this.subscribedTopics.add(topic);
      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        this.sendRaw({ type: "subscribe", event_types: [topic] });
      }
    }

    return () => this.unsubscribe(topic, handler);
  }

  unsubscribe(topic: string, handler: Handler) {
    const set = this.handlers.get(topic);
    if (!set) return;
    set.delete(handler);
    if (set.size === 0) {
      this.handlers.delete(topic);
      // We keep subscribedTopics populated — the backend treats topics additively.
    }
  }

  close() {
    this.closedByUser = true;
    if (this.reconnectTimer !== null) {
      window.clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.stopPing();
    if (this.ws) {
      try {
        this.ws.close();
      } catch {
        /* noop */
      }
      this.ws = null;
    }
    this.setStatus("closed");
  }
}

let _singleton: LiveWS | null = null;

function buildWsUrl(): string {
  const apiBase = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000/api/v1";
  // Strip trailing /api/v1 to get the root
  const root = apiBase.replace(/\/api\/v1\/?$/, "");
  const wsRoot = root.replace(/^http:/, "ws:").replace(/^https:/, "wss:");
  let clientId = "anonymous";
  if (typeof window !== "undefined") {
    clientId = localStorage.getItem("aegis_client_id") || "dashboard-live";
  }
  return `${wsRoot}/ws?client_id=${encodeURIComponent(clientId)}`;
}

export function getLiveWS(): LiveWS {
  if (!_singleton) {
    _singleton = new LiveWS(buildWsUrl());
    if (typeof window !== "undefined") {
      _singleton.connect();
    }
  }
  return _singleton;
}

/**
 * React-friendly hook wrapper (used by widgets).
 * Subscribes on mount, cleans up on unmount.
 */
export function subscribeTopic(topic: string, handler: Handler): () => void {
  const ws = getLiveWS();
  return ws.subscribe(topic, handler);
}
