import { useState, useEffect } from "react";
import styles from "./PasswordManagerPage.module.css";

const OWNER = "Uday517";
const REPO  = "Password-Manager";
const API   = `https://api.github.com/repos/${OWNER}/${REPO}/releases/latest`;
const GH    = `https://github.com/${OWNER}/${REPO}`;

const PLATFORMS = {
  mac:   { label: "macOS",   ext: ".dmg", icon: AppleIcon,   match: (ua) => /mac/i.test(ua) },
  win:   { label: "Windows", ext: ".msi", icon: WindowsIcon, match: (ua) => /win/i.test(ua) },
  linux: { label: "Linux",   ext: ".deb", icon: LinuxIcon,   match: ()   => true },
};

function detectOS() {
  const ua = navigator.userAgent;
  for (const [key, p] of Object.entries(PLATFORMS)) if (p.match(ua)) return key;
  return "linux";
}

const FEATURES = [
  {
    icon: LockIcon,
    title: "AES-256-GCM Encryption",
    desc: "Every credential is encrypted before it touches disk. PBKDF2 with 65 536 iterations derives your vault key from your master password.",
  },
  {
    icon: OfflineIcon,
    title: "Fully Offline",
    desc: "Zero cloud, zero telemetry, zero accounts. Your vault is a single SQLite file that never leaves your machine.",
  },
  {
    icon: PlatformIcon,
    title: "Cross-Platform",
    desc: "Native installers for macOS, Windows, and Linux — built automatically by GitHub Actions on every release.",
  },
  {
    icon: ShieldIcon,
    title: "Auto-Lock & Clipboard Guard",
    desc: "The vault locks itself after inactivity. Copied passwords clear from your clipboard automatically.",
  },
];

export default function PasswordManagerPage() {
  const [os, setOS]           = useState("mac");
  const [release, setRelease] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setOS(detectOS());
    fetch(API)
      .then((r) => r.json())
      .then((data) => {
        if (data.assets) setRelease(data);
      })
      .finally(() => setLoading(false));
  }, []);

  function getAssetUrl(ext) {
    if (!release) return `${GH}/releases/latest`;
    const asset = release.assets.find((a) => a.name.toLowerCase().endsWith(ext));
    return asset?.browser_download_url ?? `${GH}/releases/latest`;
  }

  const version = release ? release.tag_name : "";

  return (
    <div className={styles.page}>
      {/* ── NAV ───────────────────────────────────────────────── */}
      <nav className={styles.nav}>
        <span className={styles.navLogo}>
          <VaultIcon className={styles.navLogoIcon} />
          Vault
        </span>
        <a href={GH} target="_blank" rel="noreferrer" className={styles.navLink}>
          <GithubIcon /> GitHub
        </a>
      </nav>

      {/* ── HERO ──────────────────────────────────────────────── */}
      <section className={styles.hero}>
        <div className={styles.heroBadge}>Open Source · Local First · AES-256-GCM</div>
        <h1 className={styles.heroTitle}>
          Your passwords,<br />
          <span className={styles.heroAccent}>nowhere else.</span>
        </h1>
        <p className={styles.heroSub}>
          Vault is a desktop password manager that never phones home.
          Everything is encrypted and stored locally — only you hold the key.
        </p>

        <div className={styles.downloadGroup}>
          {loading ? (
            <div className={styles.btnPrimary} style={{ opacity: 0.5, cursor: "default" }}>
              Fetching release…
            </div>
          ) : (
            <a
              href={getAssetUrl(PLATFORMS[os].ext)}
              className={styles.btnPrimary}
              download
            >
              {(() => { const Icon = PLATFORMS[os].icon; return <Icon className={styles.btnIcon} />; })()}
              Download for {PLATFORMS[os].label}
              {version && <span className={styles.btnVersion}>{version}</span>}
            </a>
          )}

          <div className={styles.altLinks}>
            Also available for&nbsp;
            {Object.entries(PLATFORMS)
              .filter(([k]) => k !== os)
              .map(([k, p], i, arr) => (
                <span key={k}>
                  <a href={getAssetUrl(p.ext)} download className={styles.altLink}>
                    {p.label}
                  </a>
                  {i < arr.length - 1 && " · "}
                </span>
              ))}
          </div>
        </div>
      </section>

      {/* ── APP MOCKUP ────────────────────────────────────────── */}
      <section className={styles.mockupSection}>
        <div className={styles.windowChrome}>
          <div className={styles.windowDots}>
            <span className={styles.dot} style={{ background: "#ff5f56" }} />
            <span className={styles.dot} style={{ background: "#ffbd2e" }} />
            <span className={styles.dot} style={{ background: "#27c93f" }} />
          </div>
          <div className={styles.windowTitle}>Vault — Password Manager</div>
        </div>
        <div className={styles.mockupBody}>
          <div className={styles.mockupSidebar}>
            <div className={styles.mockupSidebarItem + " " + styles.active}>All Passwords</div>
            <div className={styles.mockupSidebarItem}>Favourites</div>
            <div className={styles.mockupSidebarItem}>Recent</div>
          </div>
          <div className={styles.mockupMain}>
            {["GitHub", "Google Account", "AWS Console", "Linear", "Figma"].map((name, i) => (
              <div key={i} className={styles.mockupRow}>
                <div className={styles.mockupAvatar}>{name[0]}</div>
                <div>
                  <div className={styles.mockupRowTitle}>{name}</div>
                  <div className={styles.mockupRowSub}>{"user@example.com"}</div>
                </div>
                <div className={styles.mockupRowDots}>•••••••••••</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── FEATURES ──────────────────────────────────────────── */}
      <section className={styles.features}>
        <h2 className={styles.sectionTitle}>Built for security, not convenience</h2>
        <div className={styles.featuresGrid}>
          {FEATURES.map(({ icon: Icon, title, desc }) => (
            <div key={title} className={styles.featureCard}>
              <div className={styles.featureIconWrap}>
                <Icon className={styles.featureIcon} />
              </div>
              <h3 className={styles.featureTitle}>{title}</h3>
              <p className={styles.featureDesc}>{desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── ALL DOWNLOADS ─────────────────────────────────────── */}
      <section className={styles.allDownloads}>
        <h2 className={styles.sectionTitle}>Download</h2>
        <div className={styles.platformGrid}>
          {Object.entries(PLATFORMS).map(([key, p]) => {
            const Icon = p.icon;
            const isRec = key === os;
            return (
              <a
                key={key}
                href={getAssetUrl(p.ext)}
                download
                className={`${styles.platformCard} ${isRec ? styles.platformCardRec : ""}`}
              >
                <Icon className={styles.platformIcon} />
                <span className={styles.platformLabel}>{p.label}</span>
                <span className={styles.platformExt}>{p.ext} installer</span>
                {isRec && <span className={styles.recBadge}>Recommended for your system</span>}
              </a>
            );
          })}
        </div>
        <p className={styles.sourceNote}>
          Free and open source ·{" "}
          <a href={`${GH}/releases`} target="_blank" rel="noreferrer" className={styles.sourceLink}>
            All releases on GitHub →
          </a>
        </p>
      </section>

      {/* ── FOOTER ────────────────────────────────────────────── */}
      <footer className={styles.footer}>
        <span>Built by Uday · <a href={GH} target="_blank" rel="noreferrer">Source on GitHub</a></span>
      </footer>
    </div>
  );
}

/* ── Inline SVG icons (no extra deps) ──────────────────────────── */
function VaultIcon({ className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <rect x="3" y="3" width="18" height="18" rx="3" />
      <circle cx="12" cy="12" r="3" />
      <path d="M12 9V7M12 17v-2M9 12H7M17 12h-2" />
    </svg>
  );
}
function GithubIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" style={{ marginRight: 6 }}>
      <path d="M12 2C6.477 2 2 6.477 2 12c0 4.418 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.603-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0112 6.836c.85.004 1.705.114 2.504.336 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.202 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.161 22 16.416 22 12c0-5.523-4.477-10-10-10z" />
    </svg>
  );
}
function LockIcon({ className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <rect x="5" y="11" width="14" height="10" rx="2" />
      <path d="M8 11V7a4 4 0 018 0v4" />
      <circle cx="12" cy="16" r="1" fill="currentColor" />
    </svg>
  );
}
function OfflineIcon({ className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M3 12a9 9 0 1018 0A9 9 0 003 12z" />
      <path d="M3 12h18M12 3c-4 3-4 15 0 18M12 3c4 3 4 15 0 18" />
      <line x1="3" y1="3" x2="21" y2="21" strokeWidth="1.5" />
    </svg>
  );
}
function PlatformIcon({ className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <rect x="2" y="4" width="20" height="14" rx="2" />
      <path d="M8 20h8M12 18v2" />
    </svg>
  );
}
function ShieldIcon({ className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M12 3l7 4v5c0 4.5-3 8-7 9-4-1-7-4.5-7-9V7l7-4z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  );
}
function AppleIcon({ className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor">
      <path d="M18.71 19.5c-.83 1.24-1.71 2.45-3.05 2.47-1.34.03-1.77-.79-3.29-.79-1.53 0-2 .77-3.27.82-1.31.05-2.3-1.32-3.14-2.53C4.25 17 2.94 12.45 4.7 9.39c.87-1.52 2.43-2.48 4.12-2.51 1.28-.02 2.5.87 3.29.87.78 0 2.26-1.07 3.8-.91.65.03 2.47.26 3.64 1.98-.09.06-2.17 1.28-2.15 3.81.03 3.02 2.65 4.03 2.68 4.04-.03.07-.42 1.44-1.38 2.83M13 3.5c.73-.83 1.94-1.46 2.94-1.5.13 1.17-.34 2.35-1.04 3.19-.69.85-1.83 1.51-2.95 1.42-.15-1.15.41-2.35 1.05-3.11z" />
    </svg>
  );
}
function WindowsIcon({ className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor">
      <path d="M3 5.6L10.3 4.5V11.5H3V5.6ZM11.1 4.4L21 2.8V11.4H11.1V4.4ZM3 12.5H10.3V19.5L3 18.4V12.5ZM11.1 12.6H21V21.2L11.1 19.6V12.6Z" />
    </svg>
  );
}
function LinuxIcon({ className }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor">
      <path d="M12.504 0c-.155 0-.315.008-.48.021C7.309.358 5.878 7.27 5.878 7.27s-2.35-.37-3.128 1.47c-.35.826-.429 1.79.023 2.67.078.147.171.284.274.413C2.587 12.575 1.46 13.916 1.5 15.5c.046 1.877 1.345 3.178 2.957 3.697.464.15.955.222 1.45.215.065 0 .13-.002.196-.006a5.1 5.1 0 01.494.012c.413.023.871.082 1.324.169.903.174 1.82.487 2.404.87.11.072.209.148.296.229.275.251.44.563.46.916.02.354-.112.73-.4 1.08C9.91 23.12 9.5 23.61 9.5 24h5c0-.39-.41-.88-.681-1.214-.288-.35-.42-.726-.4-1.08.02-.353.185-.665.46-.916.087-.081.185-.157.296-.229.584-.383 1.5-.696 2.404-.87.453-.087.911-.146 1.324-.169.163-.01.33-.013.494-.012.065.004.13.006.196.006.495.007.986-.065 1.45-.215 1.612-.519 2.911-1.82 2.957-3.697.04-1.584-1.087-2.925-1.547-4.15.103-.13.196-.266.274-.413.452-.88.373-1.844.023-2.67-.778-1.84-3.128-1.47-3.128-1.47S16.691.358 12.984.021A6.628 6.628 0 0012.504 0z" />
    </svg>
  );
}
