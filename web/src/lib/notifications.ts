/**
 * Desktop notifications from the paired tab (Week 14 spike).
 *
 * The browser draws the banner, so this works the same on macOS, Windows, and
 * Linux with no dependency. Authority never moves: a notification is built
 * from the server's own pending list, and the only thing a click can do is
 * message the paired tab, whose page code then calls the same protected route
 * as the on-screen button. An action button appears only where the browser
 * renders it as a distinct control (Chromium, via the service worker); a
 * plain click on the body always opens the card and approves nothing.
 */

export type NotificationSupport = "unsupported" | "default" | "granted" | "denied";

export type PendingKind = "proposal" | "approval";

export type PendingNotification = {
  kind: PendingKind;
  id: string;
  title: string;
  body: string;
  /** Label for the one-click action button; omitted when the item needs typed input. */
  decideLabel?: string;
  /** Where a plain click should land. */
  path: string;
};

export type NotificationClick = {
  action: "decide" | "open";
  kind: PendingKind;
  id: string;
  path: string;
};

export const NOTIFICATION_PREFERENCE_KEY = "sentinel.notifications.v1";
/** The only places a notification click may land; anything else falls back to the overview. */
const CLICK_PATHS = new Set(["/", "/approvals"]);
const SERVICE_WORKER_PATH = "/sentinel-sw.js";

export function notificationSupport(): NotificationSupport {
  if (typeof window === "undefined" || typeof Notification === "undefined") return "unsupported";
  return Notification.permission;
}

export function notificationsWanted(): boolean {
  if (typeof window === "undefined") return false;
  try {
    return window.localStorage.getItem(NOTIFICATION_PREFERENCE_KEY) === "on";
  } catch {
    return false;
  }
}

export function setNotificationsWanted(on: boolean) {
  try {
    window.localStorage.setItem(NOTIFICATION_PREFERENCE_KEY, on ? "on" : "off");
  } catch {
    // Private mode without storage: the preference simply does not persist.
  }
}

/** Ask once; the browser remembers the answer per origin. */
export async function requestNotificationPermission(): Promise<NotificationSupport> {
  if (notificationSupport() === "unsupported") return "unsupported";
  try {
    return await Notification.requestPermission();
  } catch {
    return Notification.permission;
  }
}

let registration: Promise<ServiceWorkerRegistration | null> | null = null;

/** Register the tiny service worker that lets Chromium show action buttons. */
export function notificationWorker(): Promise<ServiceWorkerRegistration | null> {
  if (registration) return registration;
  registration = (async () => {
    if (typeof navigator === "undefined" || !("serviceWorker" in navigator)) return null;
    try {
      const reg = await navigator.serviceWorker.register(SERVICE_WORKER_PATH);
      // `actions` is the Chromium-only part; a registration without it is
      // still fine, the notification just has no button.
      return "actions" in Notification.prototype ? reg : null;
    } catch {
      return null;
    }
  })();
  return registration;
}

/**
 * Show one notification for a pending item. Returns how it was shown so tests
 * and the settings row can tell the two paths apart.
 */
export async function showPendingNotification(
  item: PendingNotification,
  onClick: (click: NotificationClick) => void,
): Promise<"action" | "plain" | "skipped"> {
  if (notificationSupport() !== "granted" || !notificationsWanted()) return "skipped";
  const tag = `sentinel-${item.kind}-${item.id}`;
  const data = { kind: item.kind, id: item.id, path: item.path };

  const worker = await notificationWorker();
  if (worker && item.decideLabel) {
    try {
      await worker.showNotification(item.title, {
        body: item.body,
        tag,
        data,
        requireInteraction: true,
        actions: [
          { action: "decide", title: item.decideLabel },
          { action: "open", title: "Open" },
        ],
      } as NotificationOptions);
      return "action";
    } catch {
      // Fall through to the plain notification.
    }
  }

  try {
    const plain = new Notification(item.title, { body: item.body, tag, data });
    plain.onclick = () => {
      plain.close();
      window.focus();
      onClick({ action: "open", kind: item.kind, id: item.id, path: item.path });
    };
    return "plain";
  } catch {
    return "skipped";
  }
}

/** Route service-worker click messages to page code; returns an unsubscribe. */
export function listenForNotificationClicks(onClick: (click: NotificationClick) => void): () => void {
  if (typeof navigator === "undefined" || !("serviceWorker" in navigator)) return () => {};
  const handler = (event: MessageEvent) => {
    const data = event.data;
    if (!data || data.type !== "sentinel:notification") return;
    if (data.kind !== "proposal" && data.kind !== "approval") return;
    if (typeof data.id !== "string" || data.id.length === 0) return;
    onClick({
      action: data.action === "decide" ? "decide" : "open",
      kind: data.kind,
      id: data.id,
      path: typeof data.path === "string" && CLICK_PATHS.has(data.path) ? data.path : "/",
    });
  };
  navigator.serviceWorker.addEventListener("message", handler);
  return () => navigator.serviceWorker.removeEventListener("message", handler);
}
