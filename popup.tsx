import { useEffect, useState } from "react"

type Finding = {
  vulnerable: boolean
  message: string
  patchedVersion?: string
}

const VERSEL_REACT2SHELL_URL =
  "https://vercel.com/blog/resources-for-protecting-against-react2shell"

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

type VersionInfo = {
  major: number
  minor: number
  patch: number
  canary?: number
  raw: string
}

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

const checkVulnerability = (version?: string): Finding => {
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
      message: `Next.js ${parsed.raw} is vulnerable. Update to ${rule.patched} or later.`,
      patchedVersion: rule.patched
    }
  }

  return { vulnerable: false, message: `Next.js ${parsed.raw} is not flagged.` }
}

const IndexPopup = () => {
  const [version, setVersion] = useState<string | undefined>()
  const [finding, setFinding] = useState<Finding | undefined>()
  const [error, setError] = useState<string | undefined>()

  useEffect(() => {
    const fetchVersion = async () => {
      try {
        const [tab] = await chrome.tabs.query({
          active: true,
          currentWindow: true
        })
        if (!tab?.id) {
          setError("No active tab found.")
          return
        }
        const response = await chrome.runtime.sendMessage({
          type: "fetch-next-version",
          tabId: tab.id
        })
        console.info("[popup] fetch-next-version response", response)
        setVersion(response?.version)
        setFinding(checkVulnerability(response?.version))
      } catch (err) {
        setError("Unable to fetch next.version from the active tab.")
        console.error(err)
      }
    }

    fetchVersion()
  }, [])

  const statusLine = (() => {
    if (error) return error
    if (!finding) return "Detecting Next.js version on this page..."
    return finding.message
  })()

  return (
    <div
      style={{
        padding: 16,
        width: 380,
        fontFamily: "system-ui, -apple-system, Segoe UI, sans-serif"
      }}>
      <h2 style={{ marginTop: 0, marginBottom: 8 }}>Next.js react2shell detector</h2>
      <p>
        This extension locally checks the current page for <code>next.version</code> and
        compares it against the known vulnerable ranges.
      </p>
      <ul style={{ paddingLeft: 18, margin: "6px 0" }}>
        <li>Runs entirely in the browser (no network requests).</li>
        <li>Shows a red popover in-page when a vulnerable version is found.</li>
      </ul>
      <p>
        Just load any site; if it exposes a vulnerable Next.js version, the warning popover
        will appear automatically.
      </p>
      

      <div
        style={{
          marginTop: 20
        }}>
        <div style={ finding?.vulnerable ? { color: "oklch(57.7% 0.245 27.325)" } : { color: "green" }}>
          <div style={{ fontWeight: 800, marginBottom: 6 }}>
            {finding?.vulnerable ? "Vulnerable Next.js detected" : "No issues on current site"}
          </div>
          <div style={{ marginBottom: 6 }}>
            <strong>Next.js version:</strong> {version ?? "Unavailable"}
          </div>
          <div>{statusLine}</div>
          {finding?.vulnerable ? (
            <div style={{ marginTop: 8, opacity: 0.5 }}>
              We recommend contacting the creator of this page if this is not your page.
            </div>
          ) : <p style={{ fontSize: 12, opacity: 0.5, marginTop: 8 }}>
          Disclaimer: "No issues" isn't 100% guaranteed by this extension.If you own this site, still verify <code>package.json</code> (Next.js + React) is on
          patched versions.
        </p>}
        </div>
        <a
          href={VERSEL_REACT2SHELL_URL}
          target="_blank"
          rel="noreferrer"
          style={{
            display: "inline-flex",
            marginTop: 30,
            fontWeight: 600,
          }}>
          Read Vercel's guidance on React2shell
        </a>
        <div style={{ marginTop: 8, fontSize: 12, opacity: 0.8 }}>
          Built by{" "}
          <a href="https://x.com/parzerp" target="_blank" rel="noreferrer" style={{ fontWeight: 600 }}>
            @parzerp
          </a>
        </div>
      </div>
    </div>
  )
}

export default IndexPopup
