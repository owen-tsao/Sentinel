/**
 * Sentinel service worker: exists only so notifications can carry an action
 * button (Chromium requires `ServiceWorkerRegistration.showNotification` for
 * `actions`). It never talks to the backend. A click is forwarded to the
 * paired tab as a message, and page code there completes the decision through
 * the same cookie-and-Origin-protected route as the button on the card. If no
 * tab is open the click can only open one; nothing is approved.
 */
self.addEventListener("install", () => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("notificationclick", (event) => {
  const data = event.notification.data || {};
  const action = event.action === "decide" ? "decide" : "open";
  event.notification.close();
  event.waitUntil(
    (async () => {
      const windows = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
      const target = windows.find((client) => client.focused) || windows[0];
      if (!target) {
        // No paired tab: the decision cannot be made from here by design.
        await self.clients.openWindow(data.path || "/");
        return;
      }
      await target.focus();
      target.postMessage({ type: "sentinel:notification", action, kind: data.kind, id: data.id, path: data.path });
    })(),
  );
});
