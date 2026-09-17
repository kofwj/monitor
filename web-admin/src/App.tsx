import { useCallback, useEffect, useState } from "react"
import { ExternalLink, LogOut, Moon, Sun } from "lucide-react"
import { Toaster } from "sonner"

import { Admin } from "@/components/Admin"
import { Login } from "@/components/Login"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { api, provisioningSite, useNodes } from "@/lib/api"

// The fork this binary is built from, rather than the upstream project: the
// footer exists so somebody looking at a running hub can find the code that is
// actually running, and on this deployment that is not upstream.
const REPO = "https://github.com/kofwj/monitor"

type Me = { authed: boolean; github: boolean; site_name: string; public_page: boolean; site: string; can_provision: boolean; version?: string }

/** The GitHub mark, drawn locally: lucide 1.x dropped its brand icons, and no
 *  other icon set is worth a dependency just to duplicate a well-known path.
 *  The status page's footer renders the same path, so the two footers match. */
function GitHubIcon({ className }: { className?: string }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={2}
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
      aria-hidden="true"
    >
      <path d="M15 22v-4a4.8 4.8 0 0 0-1-3.5c3 0 6-2 6-5.5.08-1.25-.27-2.48-1-3.5.28-1.15.28-2.35 0-3.5 0 0-1 0-3 1.5-2.64-.5-5.36-.5-8 0C6 2 5 2 5 2c-.3 1.15-.3 2.35 0 3.5A5.403 5.403 0 0 0 4 9c0 3.5 3 5.5 6 5.5-.39.49-.68 1.05-.85 1.65-.17.6-.22 1.23-.15 1.85v4" />
      <path d="M9 18c-4.51 2-5-2-7-2" />
    </svg>
  )
}

/** What is running, and where it came from. The version is the hub's, not this
  *  bundle's: the panel has no version of its own, and the two ship in the same
  *  binary. A hub older than the field sends none, so the line is assembled from
  *  what arrived rather than leaving a separator with nothing on one side of it.
  *
  *  Shared with the login screen, which is the one page reachable without
  *  credentials and the one you land on right after an upgrade -- exactly when
  *  knowing the version matters most. */
function Footer({ version }: { version?: string }) {
  // Pinned to the viewport, not the document: a short login screen and a long
  // node list would otherwise place this line at two different heights, and
  // switching between them makes it jump. Content that would land under it
  // is padded in the pages below.
  return (
    <footer className="pointer-events-none fixed inset-x-0 bottom-0 z-10">
      <div className="mx-auto flex w-full max-w-7xl items-center px-4 py-2.5">
        <p className="pointer-events-auto flex items-center gap-x-2 rounded-md bg-background/80 px-2 py-1 text-xs text-muted-foreground backdrop-blur">
          {version && <span className="tnum">v{version}</span>}
          {version && <span aria-hidden="true">·</span>}
          {/* The address is long and noisy at footer size; a small GitHub
              icon says the same thing. The accessible name keeps the link
              meaningful to screen readers, and the tooltip restores it for
              anyone who wants to read where it goes. */}
          <a
            href={REPO}
            target="_blank"
            rel="noreferrer"
            title={`GitHub 仓库（${REPO.replace("https://github.com/", "")}）`}
            aria-label={`GitHub 仓库（${REPO.replace("https://github.com/", "")}）`}
            className="inline-flex items-center rounded p-0.5 transition-colors hover:text-foreground"
          >
            <GitHubIcon className="size-3.5" />
          </a>
        </p>
      </div>
    </footer>
  )
}

// `/admin` alone is not a page; it is normalised to the first section so that a
// bookmark and the OAuth redirect both resolve to a real route.
function normalise(p: string) {
  return p === "/admin" || p === "/admin/" ? "/admin/nodes" : p.replace(/\/$/, "") || "/admin/nodes"
}

function usePath() {
  const [path, setPath] = useState(() => {
    const start = normalise(location.pathname)
    if (start !== location.pathname) history.replaceState({}, "", start + location.search)
    return start
  })
  useEffect(() => {
    const sync = () => setPath(normalise(location.pathname))
    addEventListener("popstate", sync)
    return () => removeEventListener("popstate", sync)
  }, [])
  return [
    path,
    useCallback((next: string) => {
      const to = normalise(next)
      history.pushState({}, "", to)
      setPath(to)
    }, []),
  ] as const
}

function useTheme() {
  const [dark, setDark] = useState(() => {
    const saved = localStorage.getItem("theme")
    return saved ? saved === "dark" : matchMedia("(prefers-color-scheme: dark)").matches
  })
  useEffect(() => {
    document.documentElement.classList.toggle("dark", dark)
    localStorage.setItem("theme", dark ? "dark" : "light")
  }, [dark])
  return [dark, () => setDark((d) => !d)] as const
}

export default function App() {
  const [path, go] = usePath()
  const [dark, toggleTheme] = useTheme()
  const [me, setMe] = useState<Me | null>(null)
  const [meError, setMeError] = useState("")
  const { nodes, admin, error, refresh } = useNodes()

  const loadMe = useCallback(() => {
    // `|| "..."` because an empty message reads as no error: api() falls back to
    // res.statusText, which HTTP/2 and HTTP/3 removed, so a bodiless 502 from a
    // proxy arrives as "". The check below would then take the loading branch and
    // the retry button would never render.
    return api<Me>("/me")
      .then((next) => { setMe(next); setMeError("") })
      .catch((e: Error) => setMeError(e.message || "网络错误"))
  }, [])
  useEffect(() => {
    loadMe()
  }, [loadMe])

  // Every frame declares its audience. The hub closes the stream when the session
  // behind it is revoked -- signed out from another device, a password change, a
  // restore -- and the reconnect returns as anonymous: the public list, with
  // private nodes absent and every admin field empty, rendered inside a panel that
  // still appears signed in. `authed` is read only at mount and after signing in,
  // so nothing else detects this. /api/me already handles signing out.
  useEffect(() => {
    if (me?.authed && admin === false) loadMe()
  }, [admin, me?.authed, loadMe])

  // The tab is the one place the site name cannot come from a render. The
  // browser takes the title from the static index.html and only a script can
  // change it afterwards, so without this the tab keeps saying "Monitor 后台"
  // however the setting is renamed. The status page sets its own from the
  // theme, which is why its tab follows the setting and this one did not.
  // Falls back to the same word the static title uses, so an unset name is not
  // a visible change.
  useEffect(() => {
    document.title = `${me?.site_name || "Monitor"} 后台`
  }, [me?.site_name])

  // Only while there is nothing else to show. Login's onDone reloads /me, so a
  // transient failure in the second after signing in would otherwise replace the
  // entire signed-in panel with a full-page error while the node list streamed
  // normally.
  if (!me) return (
    <div className="grid min-h-svh place-items-center p-6 text-sm text-muted-foreground">
      {meError ? <div className="space-y-3 text-center"><p role="alert">加载失败：{meError}</p><Button onClick={loadMe}>重试</Button></div> : "加载中…"}
    </div>
  )

  if (!me.authed) {
    return (
      <>
        <Login github={me.github} onDone={() => { loadMe(); refresh(); go("/admin/nodes") }} />
        <Footer version={me.version} />
        <Toaster position="top-center" theme={dark ? "dark" : "light"} />
      </>
    )
  }

  const sorted = [...(nodes ?? [])].sort((a, b) => a.sort - b.sort || a.id - b.id)

  async function signOut() {
    await api("/auth/logout", { method: "POST" }).catch(() => {})
    location.href = "/"
  }
  return (
    <div className="min-h-svh pb-14">
      <header className="sticky top-0 z-10 border-b bg-background/80 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center gap-3 px-4 py-3">
          {/* The site name is the way back to the status page, as in the
              theme's own header. */}
          <a href="/" className="font-semibold transition-opacity hover:opacity-70">
            {me.site_name || "Monitor"}
          </a>
          <span className="text-xs text-muted-foreground">后台</span>
          <div className="flex-1" />
          {/* The status page is a separate app, so this is a navigation. */}
          <Button variant="ghost" size="sm" asChild>
            <a href="/">
              <ExternalLink /> 状态面板
            </a>
          </Button>
          <Button variant="ghost" size="icon" onClick={toggleTheme} title="切换主题">
            {dark ? <Sun /> : <Moon />}
          </Button>
          <Button variant="ghost" size="icon" onClick={signOut} title="退出登录">
            <LogOut />
          </Button>
        </div>
      </header>

      <main className="mx-auto max-w-7xl space-y-5 px-4 py-6">
        {error && <p className="text-sm text-destructive">{error}</p>}
        {!nodes ? (
          <Skeleton className="h-64" />
        ) : (
          <Admin
            path={path}
            go={go}
            nodes={sorted}
            refresh={refresh}
            // The hub's own public URL rather than this browser's address: the
            // panel is frequently reached over a loopback port behind a proxy,
            // while the install command and OAuth callback need the real one.
            site={me.site || location.origin}
            canProvision={me.can_provision && !!provisioningSite(location.origin) && !!provisioningSite(me.site || location.origin)}
            // /me carries the site name and the GitHub flag, both of which the
            // settings pages edit and this component renders. Saving has to
            // re-read it, or the header keeps the value from mount.
            refreshMe={loadMe}
          />
        )}
      </main>

      {/* What is running, and where it came from. */}
      <Footer version={me.version} />

      <Toaster position="top-center" theme={dark ? "dark" : "light"} />
    </div>
  )
}
