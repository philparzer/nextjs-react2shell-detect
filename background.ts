chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "inject-next-probe" && sender.tab?.id !== undefined) {
    console.info("[background] inject-next-probe request", sender.tab.id, sender.tab.url)
    chrome.scripting
      .executeScript({
        target: { tabId: sender.tab.id },
      world: "MAIN",
      func: () => {
        try {
          const version = (globalThis as any).next?.version ?? undefined
          window.postMessage({ source: "react2shell-next-check", version }, "*")
        } catch (error) {
          window.postMessage(
            { source: "react2shell-next-check", error: String(error) },
            "*"
          )
        }
      }
      })
      .catch((error) => {
        console.error("[background] inject-next-probe error", error)
      })
    sendResponse?.({ ok: true })
    return true
  }

  if (message?.type === "fetch-next-version") {
    const tabId = message.tabId ?? sender.tab?.id
    if (tabId === undefined) {
      sendResponse?.({ version: undefined, error: "No tab id" })
      return true
    }
    console.info("[background] fetch-next-version for tab", tabId)
    chrome.scripting
      .executeScript({
        target: { tabId },
        world: "MAIN",
        func: () => {
          try {
            return { version: (globalThis as any).next?.version ?? undefined }
          } catch (error) {
            return { error: String(error) }
          }
        }
      })
      .then(([result]) => {
        console.info("[background] fetch-next-version result", result?.result)
        sendResponse?.(result?.result ?? { version: undefined })
      })
      .catch((error) => {
        console.error("[background] fetch-next-version error", error)
        sendResponse?.({ version: undefined, error: String(error) })
      })
    return true
  }
  return false
})

// Auto-inject the probe when a tab finishes loading (best-effort).
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete") return
  if (!tab.url || tab.url.startsWith("chrome://") || tab.url.startsWith("chrome-extension://")) {
    return
  }
  console.info("[background] onUpdated inject probe", tabId, tab.url)
  chrome.scripting
    .executeScript({
      target: { tabId },
      world: "MAIN",
      func: () => {
        try {
          const version = (globalThis as any).next?.version ?? undefined
          window.postMessage({ source: "react2shell-next-check", version }, "*")
        } catch (error) {
          window.postMessage(
            { source: "react2shell-next-check", error: String(error) },
            "*"
          )
        }
      }
    })
    .catch((error) => {
      if (!tab.url?.startsWith("chrome-extension://") && !tab.url?.startsWith("chrome://newtab/")) {
        console.error("[background] Script injection failed", error?.message ?? String(error), "tab:", tab.url)
      }
    })
})


