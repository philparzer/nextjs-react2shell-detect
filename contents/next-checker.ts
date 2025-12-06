import type { PlasmoCSConfig } from "plasmo"

type VersionInfo = {
  major: number
  minor: number
  patch: number
  canary?: number
  raw: string
}

type VulnerabilityFinding = {
  vulnerable: boolean
  message: string
  patchedVersion?: string
}

export const config: PlasmoCSConfig = {
  matches: ["https://*/*", "http://*/*"]
}

// Expose the probe script so it can be injected into the page context (CSP-safe).
const PATCH_RULES: Array<{
  major: number
  minor: number
  maxPatch: number
  patched: string
}> = [
  { major: 15, minor: 0, maxPatch: 4, patched: "15.0.5" },
  { major: 15, minor: 1, maxPatch: 8, patched: "15.1.9" },
  { major: 15, minor: 2, maxPatch: 5, patched: "15.2.6" },
  { major: 15, minor: 3, maxPatch: 5, patched: "15.3.6" },
  { major: 15, minor: 4, maxPatch: 7, patched: "15.4.8" },
  { major: 15, minor: 5, maxPatch: 6, patched: "15.5.7" },
  { major: 16, minor: 0, maxPatch: 6, patched: "16.0.7" }
]

const CANARY_RULES = {
  downgrade14: {
    boundary: { major: 14, minor: 3, patch: 0, canary: 76 },
    message:
      "Next.js 14 canaries after 14.3.0-canary.76 are vulnerable. Downgrade to 14.3.0-canary.76."
  },
  next15: {
    minimumSafe: { major: 15, minor: 6, patch: 0, canary: 58 },
    message:
      "Next.js 15 canaries before 15.6.0-canary.58 are vulnerable. Update to at least 15.6.0-canary.58."
  },
  next16: {
    minimumSafe: { major: 16, minor: 1, patch: 0, canary: 12 },
    message:
      "Next.js 16 canaries before 16.1.0-canary.12 are vulnerable. Update to at least 16.1.0-canary.12."
  }
}

const POPUP_ID = "react2shell-next-warning"

const parseVersion = (raw?: string): VersionInfo | null => {
  if (!raw) return null
  const match = raw.match(
    /^(\d+)\.(\d+)\.(\d+)(?:-canary\.(\d+))?(?:[+-].*)?$/
  )
  if (!match) return null
  const [, major, minor, patch, canary] = match
  return {
    major: Number(major),
    minor: Number(minor),
    patch: Number(patch),
    canary: canary ? Number(canary) : undefined,
    raw
  }
}

const compareVersion = (
  a: VersionInfo,
  b: { major: number; minor: number; patch: number; canary?: number }
) => {
  if (a.major !== b.major) return a.major - b.major
  if (a.minor !== b.minor) return a.minor - b.minor
  if (a.patch !== b.patch) return a.patch - b.patch
  const aCanary = a.canary ?? -1
  const bCanary = b.canary ?? -1
  return aCanary - bCanary
}

let lastVersion: string | undefined
let lastFinding: VulnerabilityFinding | undefined

const checkVulnerability = (version?: string): VulnerabilityFinding => {
  const parsed = parseVersion(version)
  if (!parsed) {
    return {
      vulnerable: false,
      message: "No Next.js version detected (next.version unavailable)."
    }
  }

  if (parsed.canary !== undefined) {
    if (
      parsed.major === CANARY_RULES.downgrade14.boundary.major &&
      compareVersion(parsed, CANARY_RULES.downgrade14.boundary) > 0
    ) {
      return {
        vulnerable: true,
        message: CANARY_RULES.downgrade14.message,
        patchedVersion: "14.3.0-canary.76"
      }
    }

    if (
      parsed.major === CANARY_RULES.next15.minimumSafe.major &&
      compareVersion(parsed, CANARY_RULES.next15.minimumSafe) < 0
    ) {
      return {
        vulnerable: true,
        message: CANARY_RULES.next15.message,
        patchedVersion: "15.6.0-canary.58"
      }
    }

    if (
      parsed.major === CANARY_RULES.next16.minimumSafe.major &&
      compareVersion(parsed, CANARY_RULES.next16.minimumSafe) < 0
    ) {
      return {
        vulnerable: true,
        message: CANARY_RULES.next16.message,
        patchedVersion: "16.1.0-canary.12"
      }
    }

    return {
      vulnerable: false,
      message: `Next.js canary ${parsed.raw} is not marked as vulnerable in this check.`
    }
  }

  const rule = PATCH_RULES.find(
    (r) => r.major === parsed.major && r.minor === parsed.minor
  )
  if (rule && parsed.patch <= rule.maxPatch) {
    return {
      vulnerable: true,
      message: `Detected vulnerable Next.js version: ${parsed.raw}. Update to ${rule.patched} or later.`,
      patchedVersion: rule.patched
    }
  }

  return { vulnerable: false, message: `Next.js ${parsed.raw} not flagged.` }
}

const injectVersionProbe = () => {
  // Ask the background service worker to inject in MAIN world via chrome.scripting
  try {
    console.info("[next-checker] requesting probe injection")
    chrome?.runtime?.sendMessage?.({ type: "inject-next-probe" }, () => {
      // Ignore failures such as context invalidation during reloads
      const err = chrome.runtime.lastError
      if (err) {
        console.warn("[next-checker] probe injection sendMessage error", err.message)
      }
    })
    return
  } catch {
    // ignore and do not fallback to inline to avoid CSP errors
  }
}

const createPopover = (message: string, version?: string) => {
  if (document.getElementById(POPUP_ID)) return

  const container = document.createElement("div")
  container.id = POPUP_ID
  container.style.position = "fixed"
  container.style.top = "16px"
  container.style.right = "16px"
  container.style.zIndex = "2147483647"
  container.style.maxWidth = "320px"
  container.style.padding = "12px 14px"
  container.style.borderRadius = "12px"
  container.style.boxShadow = "0 6px 20px rgba(0,0,0,0.25)"
  container.style.background = "oklch(57.7% 0.245 27.325)"
  container.style.color = "white"
  container.style.fontFamily = "system-ui, -apple-system, Segoe UI, sans-serif"
  container.style.fontSize = "14px"
  container.style.border = "1px solid white"

  const title = document.createElement("div")
  title.textContent = "Vulnerable Next.js detected"
  title.style.fontWeight = "800"
  title.style.marginBottom = "6px"

  const detail = document.createElement("div")
  detail.textContent = message

  container.appendChild(title)
  container.appendChild(detail)

  const contact = document.createElement("div")
  contact.textContent =
    "We recommend contacting the creator of this page if this is not your page."
  contact.style.marginTop = "8px"
  contact.style.opacity = "0.75"
  container.appendChild(contact)

  const close = document.createElement("button")
  close.textContent = "Dismiss"
  close.style.marginTop = "20px"
  close.style.border = "none"
  close.style.background = "white"
  close.style.color = "black"
  close.style.padding = "6px 10px"
  close.style.fontWeight = "600"
  close.style.borderRadius = "4px"
  close.style.cursor = "pointer"
  close.addEventListener("click", () => container.remove())
  container.appendChild(close)

  document.body.appendChild(container)
}

const handleVersionMessage = (event: MessageEvent) => {
  if (event.source !== window) return
  if (!event.data || event.data.source !== "react2shell-next-check") return

  const version = event.data.version as string | undefined
  console.info("[next-checker] received version from probe", version)
  const result = checkVulnerability(version)
  lastVersion = version
  lastFinding = result

  if (result.vulnerable) {
    createPopover(result.message, version)
  }

  try {
    chrome?.runtime?.sendMessage?.({
      type: "next-version-detected",
      version,
      finding: result
    })
    console.info("[next-checker] forwarded version to runtime listeners", { version, result })
  } catch {
    // ignore
  }
}

const init = () => {
  console.info("[next-checker] init content script")
  window.addEventListener("message", handleVersionMessage, false)
  if (document.readyState === "complete" || document.readyState === "interactive") {
    injectVersionProbe()
  } else {
    document.addEventListener("DOMContentLoaded", injectVersionProbe, { once: true })
  }

  try {
    chrome?.runtime?.onMessage?.addListener((message, _sender, sendResponse) => {
      console.info("[next-checker] runtime message", message)
      if (message?.type === "get-next-version") {
        sendResponse({
          version: lastVersion,
          finding: lastFinding ?? {
            vulnerable: false,
            message: "No Next.js version detected (next.version unavailable)."
          }
        })
        return true
      }
      return false
    })
  } catch {
    // ignore
  }
}

init()


