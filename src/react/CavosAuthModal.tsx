'use client';

import React, {
  useState,
  useEffect,
  useCallback,
  useRef,
  type CSSProperties,
} from 'react';
import { useCavos } from './CavosProvider';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface CavosAuthModalProps {
  open: boolean;
  onClose: () => void;
  onSuccess?: (address: string) => void;
  appName?: string;
  appLogo?: string;
  /** Logo height in px. Applies to both a custom `appLogo` (img) and the
   *  default Cavos star. Defaults to 40 (img) / 34 (star). */
  appLogoSize?: number;
  providers?: ('google' | 'apple' | 'email')[];
  emailMode?: 'magic-link' | 'otp';
  primaryColor?: string;
  /** 'light' (default) or 'dark' */
  theme?: 'light' | 'dark';
  /** Override the card background color (defaults to white/#111 per theme). */
  backgroundColor?: string;
  /** Card / button corner radius in px (card defaults to 16, buttons to 8). */
  radius?: number;
  /**
   * Render the card in-flow (no full-screen overlay/backdrop) so it can be
   * embedded as a live preview. When true, `open` is ignored (always shown).
   */
  inline?: boolean;
  /**
   * Controls the one-time "secure your account" step shown after a new
   * account is created. Defaults to 'optional'.
   *  - 'optional': show the screen with a "Skip for now" button.
   *  - 'required': show the screen without Skip.
   *  - 'off': skip the screen entirely.
   */
  secureStep?: 'optional' | 'required' | 'off';
}
// Cavos wordmark (vectorial). Extracted from the official brand SVG with the
// fill switched to currentColor so it inherits the surrounding text color and
// works in both light and dark themes without filter hacks.
//
// Width is derived from the viewBox aspect ratio (525.61 / 81) so the flexbox
// footer can't collapse or squash it — the deformation we hit before came from
// leaving width implicit inside a justify-content:center container.
const CAVOS_ASPECT = 66 / 82; // icon mark is taller than wide

function CavosWordmark({ height = 15, color = 'currentColor' }: { height?: number; color?: string }) {
  const width = Math.round(height * CAVOS_ASPECT);
  return (
    <svg
      width={width}
      height={height}
      viewBox="0 0 66 82"
      fill={color}
      xmlns="http://www.w3.org/2000/svg"
      style={{ display: 'block', flexShrink: 0 }}
      aria-label="Cavos"
      role="img"
    >
      <g transform="translate(0,82) scale(0.1,-0.1)">
        <path d="M148 630 l-148 -185 68 -3 c193 -9 236 39 230 264 l-3 108 -147 -184z M360 705 c1 -225 37 -269 217 -263 l83 3 -136 170 c-74 94 -142 177 -150 185 -12 12 -14 0 -14 -95z M125 223 c69 -87 136 -171 150 -188 l26 -30 -4 135 c-6 212 -29 240 -201 240 l-96 0 125 -157z M433 364 c-53 -26 -67 -70 -71 -224 -3 -118 -2 -133 11 -120 8 8 76 93 151 188 l136 172 -97 0 c-68 0 -108 -5 -130 -16z" />
      </g>
    </svg>
  );
}

// Cavos star mark (the 4-point pinwheel). Uses currentColor so it adapts to the
// modal's theme text color — black on light, white on dark.
function CavosStar({ size = 34 }: { size?: number }) {
  return (
    <svg
      width={Math.round(size * (66 / 82))}
      height={size}
      viewBox="0 0 66 82"
      fill="currentColor"
      xmlns="http://www.w3.org/2000/svg"
      style={{ display: 'block' }}
      aria-label="Cavos"
      role="img"
    >
      <g transform="translate(0,82) scale(0.1,-0.1)">
        <path d="M148 630 l-148 -185 68 -3 c193 -9 236 39 230 264 l-3 108 -147 -184z M360 705 c1 -225 37 -269 217 -263 l83 3 -136 170 c-74 94 -142 177 -150 185 -12 12 -14 0 -14 -95z M125 223 c69 -87 136 -171 150 -188 l26 -30 -4 135 c-6 212 -29 240 -201 240 l-96 0 125 -157z M433 364 c-53 -26 -67 -70 -71 -224 -3 -118 -2 -133 11 -120 8 8 76 93 151 188 l136 172 -97 0 c-68 0 -108 -5 -130 -16z" />
      </g>
    </svg>
  );
}

type Screen =
  | 'select'
  | 'magic-link'
  | 'verify'
  | 'otp-code'
  | 'deploying'
  | 'device-approval'
  | 'passkey-approval'
  | 'recover'
  | 'secure-account'
  | 'recovery-code';

// ─── Style injection ──────────────────────────────────────────────────────────

const STYLE_ID = 'cavos-modal-styles-v2';

function injectStyles() {
  if (typeof document === 'undefined') return;
  if (document.getElementById(STYLE_ID)) return;
  const el = document.createElement('style');
  el.id = STYLE_ID;
  el.textContent = `
    @keyframes cavos-fade { from { opacity:0; } to { opacity:1; } }
    @keyframes cavos-up {
      from { opacity:0; transform:translateY(12px) scale(0.985); }
      to   { opacity:1; transform:translateY(0)    scale(1);     }
    }
    @keyframes cavos-sheet {
      from { transform:translateY(100%); }
      to   { transform:translateY(0); }
    }
    @keyframes cavos-spin {
      from { transform:rotate(0deg); } to { transform:rotate(360deg); }
    }
    @keyframes cavos-pop {
      0%   { transform:scale(0.5);  opacity:0; }
      60%  { transform:scale(1.12); opacity:1; }
      100% { transform:scale(1);    opacity:1; }
    }
    @keyframes cavos-check-draw {
      from { stroke-dashoffset: 30; }
      to   { stroke-dashoffset: 0;  }
    }
    @keyframes cavos-ring-glow {
      0%,100% { box-shadow: 0 0 0 0 rgba(34,197,94,0.4); }
      50%      { box-shadow: 0 0 0 10px rgba(34,197,94,0); }
    }
    .cavos-check-circle {
      animation: cavos-pop 0.45s cubic-bezier(.22,1,.36,1) forwards;
    }
    .cavos-check-path {
      stroke-dasharray: 30;
      stroke-dashoffset: 30;
      animation: cavos-check-draw 0.35s 0.2s cubic-bezier(.22,1,.36,1) forwards;
    }
    .cavos-input-inner:focus { outline:none; }
    .cavos-provider:active { transform:scale(0.99); }
    .cavos-primary-btn:active { transform:scale(0.98); }
    .cavos-otp-input {
      width: 100%;
      text-align: center;
      font-size: 22px;
      font-weight: 600;
      background: transparent;
      border: none;
      outline: none;
      color: inherit;
      font-family: inherit;
      caret-color: transparent;
    }
    .cavos-otp-box {
      transition: border-color 0.15s, box-shadow 0.15s, transform 0.1s;
    }
    .cavos-otp-box-filled {
      transform: scale(1.04);
    }
    .cavos-divider-line {
      flex: 1;
      height: 1px;
    }
    /* Theme-aware interaction styles. The overlay carries data-cavos-theme so
       hovers/focus rings stay legible in both light and dark — the previous
       rgba(0,0,0,…) rules disappeared against the dark background. */
    [data-cavos-theme="light"] .cavos-input-row:focus-within {
      border-color: rgba(0,0,0,0.35) !important;
      box-shadow: 0 0 0 3px rgba(0,0,0,0.06) !important;
    }
    [data-cavos-theme="dark"] .cavos-input-row:focus-within {
      border-color: rgba(255,255,255,0.45) !important;
      box-shadow: 0 0 0 3px rgba(255,255,255,0.08) !important;
    }
    [data-cavos-theme="light"] .cavos-provider:hover { background: rgba(0,0,0,0.035) !important; }
    [data-cavos-theme="dark"]  .cavos-provider:hover { background: rgba(255,255,255,0.07) !important; }
    [data-cavos-theme="light"] .cavos-close:hover { background: rgba(0,0,0,0.05) !important; }
    [data-cavos-theme="dark"]  .cavos-close:hover { background: rgba(255,255,255,0.08) !important; }
    [data-cavos-theme="light"] .cavos-sub-btn:hover { color: rgba(0,0,0,0.6) !important; }
    [data-cavos-theme="dark"]  .cavos-sub-btn:hover { color: rgba(255,255,255,0.65) !important; }
    [data-cavos-theme="light"] .cavos-submit-btn:hover { color: rgba(0,0,0,0.8) !important; }
    [data-cavos-theme="dark"]  .cavos-submit-btn:hover { color: rgba(255,255,255,0.85) !important; }
    [data-cavos-theme="light"] .cavos-primary-btn:hover { opacity: 0.88; }
    [data-cavos-theme="dark"]  .cavos-primary-btn:hover { opacity: 0.9; }
    [data-cavos-theme="light"] .cavos-divider-line { background: rgba(0,0,0,0.08); }
    [data-cavos-theme="dark"]  .cavos-divider-line { background: rgba(255,255,255,0.1); }
  `;
  document.head.appendChild(el);
}

// ─── Icons ────────────────────────────────────────────────────────────────────

const GoogleIcon = () => (
  <svg width="18" height="18" viewBox="0 0 18 18" fill="none">
    <path d="M17.64 9.2c0-.637-.057-1.251-.164-1.84H9v3.481h4.844c-.209 1.125-.843 2.078-1.796 2.717v2.258h2.908c1.702-1.567 2.684-3.875 2.684-6.615z" fill="#4285F4"/>
    <path d="M9 18c2.43 0 4.467-.806 5.956-2.184l-2.908-2.258c-.806.54-1.837.86-3.048.86-2.344 0-4.328-1.584-5.036-3.711H.957v2.332A8.997 8.997 0 009 18z" fill="#34A853"/>
    <path d="M3.964 10.707A5.41 5.41 0 013.682 9c0-.593.102-1.17.282-1.707V4.961H.957A8.996 8.996 0 000 9c0 1.452.348 2.827.957 4.039l3.007-2.332z" fill="#FBBC05"/>
    <path d="M9 3.58c1.321 0 2.508.454 3.44 1.345l2.582-2.58C13.463.891 11.426 0 9 0A8.997 8.997 0 00.957 4.961L3.964 7.293C4.672 5.163 6.656 3.58 9 3.58z" fill="#EA4335"/>
  </svg>
);

const AppleIcon = () => (
  <svg width="16" height="16" viewBox="0 0 814 1000" fill="currentColor">
    <path d="M788.1 340.9c-5.8 4.5-108.2 62.2-108.2 190.5 0 148.4 130.3 200.9 134.2 202.2-.6 3.2-20.7 71.9-68.7 141.9-42.8 61.6-87.5 123.1-155.5 123.1s-85.5-39.5-164-39.5c-76 0-103.7 40.8-165.9 40.8s-105-57.8-155.5-127.4C46 790.7 0 663 0 541.8c0-194.3 126.4-297.5 250.8-297.5 66.1 0 121.2 43.4 162.7 43.4 39.5 0 101.1-46 176.3-46 28.5 0 130.9 2.6 198.3 99.2zm-234-181.5c31.1-36.9 53.1-88.1 53.1-139.3 0-7.1-.6-14.3-1.9-20.1-50.6 1.9-110.8 33.7-147.1 75.8-28.5 32.4-55.1 83.6-55.1 135.5 0 7.8 1.3 15.6 1.9 18.1 3.2.6 8.4 1.3 13.6 1.3 45.4 0 102.5-30.4 135.5-71.3z"/>
  </svg>
);

const EmailIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
    <rect x="2" y="4" width="20" height="16" rx="2"/>
    <path d="m22 7-8.97 5.7a1.94 1.94 0 01-2.06 0L2 7"/>
  </svg>
);

// Clean monochrome fingerprint (Lucide). Inherits the surrounding ink color so
// it stays on-brand in both themes — no colored circles.
const FingerprintIcon = ({ size = 22, color = 'currentColor' }: { size?: number; color?: string }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
    <path d="M2 12C2 6.5 6.5 2 12 2a10 10 0 0 1 8 4" />
    <path d="M5 19.5C5.5 18 6 15 6 12c0-.7.12-1.37.34-2" />
    <path d="M17.29 21.02c.12-.6.43-2.3.5-3.02" />
    <path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4" />
    <path d="M8.65 22c.21-.66.45-1.32.57-2" />
    <path d="M14 13.12c0 2.38 0 6.38-1 8.88" />
    <path d="M2 16h.01" />
    <path d="M21.8 16c.2-2 .131-5.354 0-6" />
    <path d="M9 6.8a6 6 0 0 1 9 5.2c0 .47 0 1.17-.02 2" />
  </svg>
);

// ─── Branded icons (Cavos electric-indigo) ──────────────────────────────────
// Solid brand-colored marks with white cut-out details — no pastel discs, no
// thin strokes. They read as part of the Cavos brand, like the product logo.
const BRAND = '#402AFF';

// Plain centering wrapper (no background circle) — the icon itself carries the color.
function BrandBadge({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ margin: '0 auto 18px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      {children}
    </div>
  );
}

const BrandShield = ({ size = 46, tone = BRAND }: { size?: number; tone?: string }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
    <path d="M12 2.1l7.7 3.06a1 1 0 0 1 .63.93v5.02c0 4.96-3.28 8.52-7.98 10.18a1.05 1.05 0 0 1-.7 0C6.95 19.63 3.67 16.07 3.67 11.11V6.09a1 1 0 0 1 .63-.93L12 2.1z" fill={tone} />
    <path d="M8.4 12.1l2.55 2.55 4.85-5.1" stroke="#fff" strokeWidth="2.1" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

const BrandFingerprint = ({ size = 46 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
    <circle cx="12" cy="12" r="10" fill={BRAND} />
    <g stroke="#fff" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M6.4 10.6A6.4 6.4 0 0 1 12 6.2a6.3 6.3 0 0 1 4.8 2.15" />
      <path d="M8.2 16.8c.45-1.15.7-2.6.7-4a3.8 3.8 0 0 1 .25-1.35" />
      <path d="M12 10.3a2 2 0 0 0-2 2c0 1.4-.17 3-.55 4.35" />
      <path d="M15 12.2c0 2.2-.27 4.3-.85 6" />
      <path d="M16.9 16.6c.27-1.3.4-2.65.4-3.95a5.3 5.3 0 0 0-8-4.55" />
    </g>
  </svg>
);

const BrandPhone = ({ size = 46, tone = BRAND }: { size?: number; tone?: string }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
    <rect x="6" y="2" width="12" height="20" rx="3.2" fill={tone} />
    <path d="M10 4.6h4" stroke="#fff" strokeWidth="1.4" strokeLinecap="round" strokeOpacity="0.7" />
    <circle cx="12" cy="18.6" r="1.15" fill="#fff" />
  </svg>
);

const BrandKey = ({ size = 46 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
    <path d="M14.5 3a6.5 6.5 0 0 0-6.27 8.2L3 16.43V21h4.5v-2.2h2.2v-2.2h1.86A6.5 6.5 0 1 0 14.5 3z" fill={BRAND} />
    <circle cx="16.2" cy="7.8" r="1.7" fill="#fff" />
  </svg>
);

function Spinner({ size = 16, color = '#888' }: { size?: number; color?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
      style={{ animation: 'cavos-spin 0.75s linear infinite', flexShrink: 0 }}>
      <circle cx="12" cy="12" r="10" stroke={color} strokeOpacity="0.2" strokeWidth="2.5"/>
      <path d="M12 2a10 10 0 0110 10" stroke={color} strokeWidth="2.5" strokeLinecap="round"/>
    </svg>
  );
}

// ─── Mobile detection hook ────────────────────────────────────────────────────

function useIsMobile() {
  const [isMobile, setIsMobile] = useState(false);
  useEffect(() => {
    const mq = window.matchMedia('(max-width: 640px)');
    setIsMobile(mq.matches);
    const handler = (e: MediaQueryListEvent) => setIsMobile(e.matches);
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, []);
  return isMobile;
}

// ─── Style helpers ────────────────────────────────────────────────────────────

const FONT = '-apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif';

function baseOverlay(isMobile: boolean): CSSProperties {
  return {
    position: 'fixed', inset: 0,
    background: 'rgba(0,0,0,0.5)',
    backdropFilter: 'blur(10px)',
    WebkitBackdropFilter: 'blur(10px)',
    zIndex: 9999,
    display: 'flex',
    alignItems: isMobile ? 'flex-end' : 'center',
    justifyContent: 'center',
    padding: isMobile ? '0' : '16px',
    animation: 'cavos-fade 0.18s ease',
    fontFamily: FONT,
  };
}

function lightCard(isMobile: boolean, bg: string, radius: number, inline: boolean): CSSProperties {
  if (inline) {
    return {
      background: bg,
      borderRadius: `${radius}px`,
      width: '100%',
      maxWidth: '400px',
      boxShadow: '0 1px 3px rgba(0,0,0,0.06), 0 0 0 1px rgba(0,0,0,0.06)',
      overflow: 'hidden',
      transition: 'background-color 0.3s ease, border-radius 0.2s ease',
    };
  }
  return isMobile ? {
    background: bg,
    borderRadius: `${radius}px ${radius}px 0 0`,
    width: '100%',
    maxWidth: '100%',
    boxShadow: '0 -8px 40px rgba(0,0,0,0.18)',
    animation: 'cavos-sheet 0.32s cubic-bezier(0.22,1,0.36,1)',
    overflow: 'hidden',
  } : {
    background: bg,
    borderRadius: `${radius}px`,
    width: '100%',
    maxWidth: '400px',
    boxShadow: '0 24px 60px rgba(0,0,0,0.22), 0 0 0 1px rgba(0,0,0,0.05)',
    animation: 'cavos-up 0.25s cubic-bezier(0.22,1,0.36,1)',
    overflow: 'hidden',
    transition: 'background-color 0.3s ease, border-radius 0.2s ease',
  };
}

function providerBtn(textColor: string, radius: number): CSSProperties {
  const isLight = textColor === '#111111' || textColor === '#111';
  return {
    width: '100%',
    display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '10px',
    padding: '12px 16px',
    background: isLight ? '#fff' : 'rgba(255,255,255,0.04)',
    border: `1px solid ${isLight ? 'rgba(0,0,0,0.12)' : 'rgba(255,255,255,0.12)'}`,
    borderRadius: `${radius}px`,
    cursor: 'pointer',
    fontSize: '14px',
    fontWeight: 500,
    color: textColor,
    fontFamily: 'inherit',
    transition: 'background 0.15s, transform 0.1s, border-color 0.15s, color 0.25s ease',
    position: 'relative',
  };
}

function footerBar(textColor: string): CSSProperties {
  const isLight = textColor === '#111111' || textColor === '#111';
  return {
    borderTop: `1px solid ${isLight ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.06)'}`,
    padding: '14px 20px',
    display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '7px',
    fontSize: '11px',
    letterSpacing: '0.01em',
    color: isLight ? 'rgba(0,0,0,0.4)' : 'rgba(255,255,255,0.4)',
  };
}

function closeBtn(textColor: string): CSSProperties {
  return {
    position: 'absolute', top: '16px', right: '16px',
    width: '28px', height: '28px', borderRadius: '50%',
    border: 'none', background: 'transparent',
    cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center',
    color: textColor === '#111111' || textColor === '#111' ? 'rgba(0,0,0,0.3)' : 'rgba(255,255,255,0.4)',
    padding: 0, transition: 'background 0.15s',
  };
}

function mobileHandle(): CSSProperties {
  return {
    width: '36px', height: '4px', borderRadius: '2px',
    background: 'rgba(0,0,0,0.15)', margin: '12px auto 0',
  };
}

const CloseX = () => (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
    <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
  </svg>
);

// ─── Main component ───────────────────────────────────────────────────────────

export function CavosAuthModal({
  open,
  onClose,
  appName,
  appLogo,
  appLogoSize,
  providers = ['google', 'apple', 'email'],
  emailMode = 'magic-link',
  primaryColor = '#402AFF',
  theme = 'light',
  backgroundColor: backgroundColorProp,
  radius,
  inline = false,
  secureStep = 'optional',
}: CavosAuthModalProps) {
  const {
    login,
    sendMagicLink,
    sendOtp,
    verifyOtp,
    isAuthenticated,
    address,
    walletStatus,
    authError,
    clearAuthError,
    resendDeviceApproval,
    recover,
    passkeySupported,
    enrollPasskeyDefault,
    approveDeviceWithPasskey,
    setupRecovery,
  } = useCavos();
  const isMobile = useIsMobile();

  // Theme-derived values
  const isLight = theme !== 'dark';
  const backgroundColor = backgroundColorProp ?? (isLight ? '#ffffff' : '#111111');
  const textColor = isLight ? '#111111' : '#ffffff';
  const subTextColor = isLight ? 'rgba(0,0,0,0.4)' : 'rgba(255,255,255,0.4)';
  const inputBg = isLight ? '#fff' : 'rgba(255,255,255,0.06)';
  const inputBorder = isLight ? '1px solid rgba(0,0,0,0.12)' : '1px solid rgba(255,255,255,0.12)';
  const errBg = isLight ? 'rgba(239,68,68,0.06)' : 'rgba(239,68,68,0.08)';
  const errColor = isLight ? '#dc2626' : '#f87171';
  const errBorder = isLight ? 'rgba(239,68,68,0.18)' : 'rgba(239,68,68,0.2)';
  const cardRadius = radius ?? 16;
  const btnRadius = Math.min(radius ?? 8, 12);
  const card = lightCard(isMobile, backgroundColor, cardRadius, inline);
  const overlay: CSSProperties = inline
    ? { display: 'flex', justifyContent: 'center', width: '100%', fontFamily: FONT }
    : baseOverlay(isMobile);
  const handle = mobileHandle();
  const footer = footerBar(textColor);
  const close = closeBtn(textColor);
  const pBtn = providerBtn(textColor, btnRadius);

  const [screen, setScreen] = useState<Screen>('select');
  const [email, setEmail] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [deployState, setDeployState] = useState<'loading' | 'done'>('loading');
  // Escape hatch: if the deploy/connect stalls (e.g. a slow Horizon read), flip
  // this after a grace period so the user gets a "taking longer" message + a way
  // back instead of an indefinite spinner.
  const [deploySlow, setDeploySlow] = useState(false);
  const [resendCountdown, setResendCountdown] = useState(0);
  const [deviceResendBusy, setDeviceResendBusy] = useState(false);
  const [recoverCode, setRecoverCode] = useState('');
  const [recoverBusy, setRecoverBusy] = useState(false);
  // Passkey / account-security flows (new-device approval + first-time upsell).
  const [pkBusy, setPkBusy] = useState(false);
  const [pkError, setPkError] = useState('');
  const [savedRecoveryCode, setSavedRecoveryCode] = useState('');
  const [copied, setCopied] = useState(false);

  const doneHandledRef = useRef(false);
  // True once the first-time "secure your account" step has been shown & handled
  // (completed or skipped) this session, so we don't loop back into it.
  const secureHandledRef = useRef(false);
  const closeTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  // One ref per OTP box for focus management / auto-advance.
  const otpBoxRefs = useRef<Array<HTMLInputElement | null>>([null, null, null, null, null, null]);

  // Segmented OTP input helpers: keep `otpCode` (6-digit string) as the single
  // source of truth, drive focus by index, and handle paste/keystrokes cleanly.
  const setOtpDigit = (i: number, raw: string) => {
    const digit = raw.replace(/\D/g, '').slice(-1);
    setOtpCode(prev => {
      const chars = prev.split('');
      while (chars.length < 6) chars.push('');
      chars[i] = digit;
      const next = chars.join('').slice(0, 6);
      // Auto-advance to the next empty box when a digit is typed.
      if (digit && i < 5) {
        const target = i + 1;
        otpBoxRefs.current[target]?.focus();
      }
      return next;
    });
  };

  const onOtpKeyDown = (i: number, e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Backspace' && !otpCode[i] && i > 0) {
      // Empty box + backspace → move focus back instead of clearing nothing.
      otpBoxRefs.current[i - 1]?.focus();
      e.preventDefault();
    } else if (e.key === 'ArrowLeft' && i > 0) {
      otpBoxRefs.current[i - 1]?.focus();
      e.preventDefault();
    } else if (e.key === 'ArrowRight' && i < 5) {
      otpBoxRefs.current[i + 1]?.focus();
      e.preventDefault();
    }
  };

  const onOtpPaste = (e: React.ClipboardEvent<HTMLInputElement>) => {
    const text = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6);
    if (!text) return;
    e.preventDefault();
    setOtpCode(text);
    // Focus the box after the last pasted digit (or the last box).
    const focusIdx = Math.min(text.length, 5);
    otpBoxRefs.current[focusIdx]?.focus();
  };

  useEffect(() => { injectStyles(); }, []);

  // When the provider surfaces an unrecoverable connect error (e.g. a failed
  // OAuth callback), drop the user back on the provider-selection screen with
  // the message + a retry, instead of leaving the modal closed with no feedback.
  useEffect(() => {
    if (!authError) return;
    setBusy(false);
    setDeployState('loading');
    if (screen !== 'device-approval') setScreen('select');
    setError(authError);
    // The provider owns the error; once surfaced here it's "consumed" by the UI.
    clearAuthError();
  }, [authError, clearAuthError, screen]);

  // Arm the "taking longer than usual" hint while the deploy spinner is up.
  useEffect(() => {
    if (screen !== 'deploying' || deployState !== 'loading') {
      setDeploySlow(false);
      return;
    }
    setDeploySlow(false);
    const t = setTimeout(() => setDeploySlow(true), 15000);
    return () => clearTimeout(t);
  }, [screen, deployState]);

  const triggerDone = useCallback((addr: string) => {
    if (doneHandledRef.current) return;
    doneHandledRef.current = true;

    setScreen('deploying');
    setDeployState('done');

    closeTimerRef.current = setTimeout(() => {
      onClose();
      setScreen('select');
      setDeployState('loading');
      setEmail(''); setOtpCode(''); setError('');
      doneHandledRef.current = false;
      secureHandledRef.current = false;
    }, 1600);
    // addr unused beyond guarding the transition; keep the param for clarity.
    void addr;
  }, [onClose]);

  // Show the "deploying" screen whenever a deploy is in progress (e.g. while
  // returning from an OAuth redirect), or once authenticated, then flip to
  // "done" when the account is ready.
  useEffect(() => {
    if (!open) return;

    if (walletStatus.isDeploying && screen !== 'deploying' && screen !== 'verify') {
      setScreen('deploying');
      setDeployState('loading');
      doneHandledRef.current = false;
    }

    if (isAuthenticated && address && walletStatus.isReady) {
      // First sign-up: offer a one-time "secure your account" step (passkey /
      // recovery phrase) before finishing — unless the app opted out via
      // secureStep: 'off'. Stay put once we've shown it.
      if (walletStatus.isNewAccount && !secureHandledRef.current && secureStep !== 'off') {
        if (screen !== 'secure-account' && screen !== 'recovery-code' && !doneHandledRef.current) {
          setScreen('secure-account');
        }
      } else {
        triggerDone(address);
      }
    }

    // This device needs approval. If the account has a passkey enrolled, offer
    // the passkey path (works on any browser); otherwise fall back to the email
    // approval flow. Don't override the recover screen — the user navigated there
    // intentionally to restore access with their recovery phrase.
    if (
      walletStatus.needsDeviceApproval &&
      // A deploy in progress owns the screen; never fight the deploying branch
      // above (both flags true would oscillate deploying ↔ approval → loop).
      !walletStatus.isDeploying &&
      screen !== 'recover' &&
      screen !== 'device-approval' &&
      screen !== 'passkey-approval'
    ) {
      if (walletStatus.hasPasskey && passkeySupported) {
        setScreen('passkey-approval');
        doneHandledRef.current = false;
      } else if (walletStatus.awaitingApproval) {
        setScreen('device-approval');
        doneHandledRef.current = false;
      }
    }
  }, [open, isAuthenticated, address, walletStatus.isReady, walletStatus.isDeploying, walletStatus.awaitingApproval, walletStatus.needsDeviceApproval, walletStatus.hasPasskey, walletStatus.isNewAccount, passkeySupported, screen, triggerDone, secureStep]);

  useEffect(() => () => {
    if (closeTimerRef.current) clearTimeout(closeTimerRef.current);
  }, []);

  const handleClose = () => {
    if (screen === 'deploying') return;
    setScreen('select'); setEmail(''); setOtpCode(''); setError('');
    setPkError(''); setSavedRecoveryCode(''); setCopied(false);
    doneHandledRef.current = false;
    secureHandledRef.current = false;
    onClose();
  };

  // ── Passkey / account-security handlers ────────────────────────────────────

  const finishSecureStep = () => {
    secureHandledRef.current = true;
    if (address) triggerDone(address);
  };

  const handleSetupPasskey = async () => {
    setPkBusy(true); setPkError('');
    try {
      await enrollPasskeyDefault();
      finishSecureStep();
    } catch (e: unknown) {
      setPkError(e instanceof Error ? e.message : "We couldn't set up your passkey. Try again.");
    } finally {
      setPkBusy(false);
    }
  };

  const handleSaveRecovery = async () => {
    setPkBusy(true); setPkError('');
    try {
      const code = await setupRecovery();
      setSavedRecoveryCode(code);
      setScreen('recovery-code');
    } catch (e: unknown) {
      setPkError(e instanceof Error ? e.message : "We couldn't create your recovery phrase. Try again.");
    } finally {
      setPkBusy(false);
    }
  };

  const handleCopyRecovery = async () => {
    try {
      await navigator.clipboard.writeText(savedRecoveryCode);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard blocked — the user can still select the text manually */
    }
  };

  const handlePasskeyApprove = async () => {
    setPkBusy(true); setPkError('');
    try {
      await approveDeviceWithPasskey();
      // approveDeviceWithPasskey reconnects → walletStatus flips to ready and the
      // status effect drives the "deploying" → done transition. Always drop the
      // busy flag so we never freeze on "Verifying…" if the modal lands back on
      // the passkey screen (e.g. on-chain indexing lag) — the user can retry.
      setPkBusy(false);
    } catch (e: unknown) {
      setPkError(e instanceof Error ? e.message : "We couldn't verify your passkey. Try again or use email.");
      setPkBusy(false);
    }
  };

  const handleOAuth = async (provider: 'google' | 'apple') => {
    setError(''); setBusy(true);
    try {
      await login(provider);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Authentication failed.';
      setError(msg); setBusy(false);
    }
  };

  const handleMagicLinkSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) return;
    setError(''); setBusy(true);
    try {
      await sendMagicLink(email);
      setScreen('verify');
      setResendCountdown(60);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to send magic link.');
    } finally {
      setBusy(false);
    }
  };

  const handleOtpRequestSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) return;
    setError(''); setBusy(true);
    try {
      await sendOtp(email);
      setOtpCode('');
      setScreen('otp-code');
      setResendCountdown(60);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to send code.');
    } finally {
      setBusy(false);
    }
  };

  const handleOtpVerifySubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || otpCode.length !== 6) return;
    setError(''); setBusy(true);
    try {
      await verifyOtp(email, otpCode);
      setScreen('deploying');
      setDeployState('loading');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Invalid or expired code.');
      setBusy(false);
    }
  };

  const handleResend = async () => {
    if (resendCountdown > 0) return;
    setError('');
    try {
      if (emailMode === 'otp') {
        await sendOtp(email);
        setOtpCode('');
      } else {
        await sendMagicLink(email);
      }
      setResendCountdown(60);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to resend.');
    }
  };

  useEffect(() => {
    if (resendCountdown <= 0) return;
    const t = setTimeout(() => setResendCountdown(c => c - 1), 1000);
    return () => clearTimeout(t);
  }, [resendCountdown]);

  if (!open && !inline) return null;

  // ── Device approval (waiting for the owner to approve from another device) ─

  const handleDeviceResend = async () => {
    if (resendCountdown > 0 || deviceResendBusy) return;
    setDeviceResendBusy(true);
    setError('');
    try {
      await resendDeviceApproval();
      setResendCountdown(60);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to resend. Try again.');
    } finally {
      setDeviceResendBusy(false);
    }
  };

  // ── Shared footer (Secured by Cavos) ───────────────────────────────────────
  // This is the kit's own branding (Cavos as the infrastructure provider), NOT
  // the integrating app's logo. Like "Powered by Stripe" — it always shows the
  // Cavos wordmark. The SVG uses currentColor so it matches the text tone in
  // both light and dark themes.
  const renderFooter = () => (
    <div style={{ ...footer, color: isLight ? 'rgba(0,0,0,0.45)' : 'rgba(255,255,255,0.48)' }}>
      <span style={{ fontSize: '11px' }}>Secured by</span>
      <CavosWordmark height={13} color="currentColor" />
    </div>
  );

  // ── Secure your account (one-time, first sign-up) ─────────────────────────

  if (screen === 'secure-account') {
    return (
      <div style={overlay} data-cavos-theme={theme} role="dialog" aria-modal>
        <div style={{ ...card, position: 'relative' }}>
          {isMobile && <div style={handle} />}
          <div style={{ padding: isMobile ? '28px 24px 28px' : '44px 24px 28px', textAlign: 'center' }}>
            <BrandBadge><BrandShield /></BrandBadge>
            <h2 style={{ margin: '0 0 8px', fontSize: '17px', fontWeight: 600, color: textColor, letterSpacing: '-0.02em' }}>
              Keep your account safe
            </h2>
            <p style={{ margin: '0 0 24px', fontSize: '13px', color: subTextColor, lineHeight: 1.55 }}>
              Set up a passkey so you can sign in on a new phone or computer in one tap. It takes a few seconds.
            </p>
            {pkError && <div style={{ background: errBg, border: `1px solid ${errBorder}`, borderRadius: '10px', padding: '9px 13px', fontSize: '13px', color: errColor, marginBottom: '14px', textAlign: 'left' }}>{pkError}</div>}

            {passkeySupported ? (
              <>
                <button className="cavos-primary-btn" style={{ width: '100%', padding: '13px', borderRadius: `${btnRadius}px`, border: 'none', background: primaryColor, color: '#fff', fontSize: '14px', fontWeight: 600, cursor: pkBusy ? 'default' : 'pointer', fontFamily: 'inherit', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '9px', opacity: pkBusy ? 0.65 : 1, transition: 'opacity 0.15s, transform 0.1s' }} onClick={handleSetupPasskey} disabled={pkBusy}>
                  {pkBusy ? <Spinner size={16} color="#fff" /> : <FingerprintIcon size={18} color="#fff" />}
                  {pkBusy ? 'Setting up…' : 'Set up a passkey'}
                </button>
                <p style={{ margin: '10px 0 0', fontSize: '12px', color: subTextColor, lineHeight: 1.5 }}>
                  Uses Face ID, Touch ID, or your device PIN.
                </p>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px', margin: '18px 0' }}>
                  <span className="cavos-divider-line" style={{ background: isLight ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.1)' }} />
                  <span style={{ fontSize: '11px', color: subTextColor, textTransform: 'uppercase', letterSpacing: '0.06em' }}>or</span>
                  <span className="cavos-divider-line" style={{ background: isLight ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.1)' }} />
                </div>
                <button className="cavos-submit-btn" style={{ width: '100%', padding: '12px', borderRadius: `${btnRadius}px`, border: inputBorder, background: 'transparent', color: textColor, fontSize: '14px', fontWeight: 500, cursor: pkBusy ? 'default' : 'pointer', fontFamily: 'inherit', transition: 'background 0.15s', opacity: pkBusy ? 0.6 : 1 }} onClick={handleSaveRecovery} disabled={pkBusy}>
                  Save a recovery phrase instead
                </button>
              </>
            ) : (
              <button className="cavos-primary-btn" style={{ width: '100%', padding: '13px', borderRadius: `${btnRadius}px`, border: 'none', background: primaryColor, color: '#fff', fontSize: '14px', fontWeight: 600, cursor: pkBusy ? 'default' : 'pointer', fontFamily: 'inherit', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '9px', opacity: pkBusy ? 0.65 : 1, transition: 'opacity 0.15s' }} onClick={handleSaveRecovery} disabled={pkBusy}>
                {pkBusy && <Spinner size={16} color="#fff" />}
                {pkBusy ? 'Setting up…' : 'Save a recovery phrase'}
              </button>
            )}

            {secureStep !== 'required' && (
              <button className="cavos-sub-btn" style={{ background: 'none', border: 'none', cursor: pkBusy ? 'default' : 'pointer', fontSize: '13px', color: subTextColor, width: '100%', textAlign: 'center', padding: '18px 0 0', fontFamily: 'inherit', transition: 'color 0.15s', opacity: pkBusy ? 0.6 : 1 }} onClick={finishSecureStep} disabled={pkBusy}>
                Skip for now
              </button>
            )}
          </div>
          {renderFooter()}
        </div>
      </div>
    );
  }

  // ── Recovery phrase reveal (save it once) ─────────────────────────────────

  if (screen === 'recovery-code') {
    return (
      <div style={overlay} data-cavos-theme={theme} role="dialog" aria-modal>
        <div style={{ ...card, position: 'relative' }}>
          {isMobile && <div style={handle} />}
          <div style={{ padding: isMobile ? '28px 24px 28px' : '44px 24px 28px', textAlign: 'center' }}>
            <h2 style={{ margin: '0 0 8px', fontSize: '17px', fontWeight: 600, color: textColor, letterSpacing: '-0.02em' }}>
              Save your recovery phrase
            </h2>
            <p style={{ margin: '0 0 18px', fontSize: '13px', color: subTextColor, lineHeight: 1.55 }}>
              Write this down and keep it somewhere safe. It's the only way to get back in if you lose your devices, and we can't recover it for you.
            </p>
            <div style={{ background: isLight ? 'rgba(0,0,0,0.03)' : 'rgba(255,255,255,0.05)', border: `1px solid ${isLight ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.1)'}`, borderRadius: `${btnRadius}px`, padding: '16px', marginBottom: '12px', fontSize: '14px', fontWeight: 500, color: textColor, wordBreak: 'break-word', lineHeight: 1.6, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', textAlign: 'center' }}>
              {savedRecoveryCode}
            </div>
            <button className="cavos-provider" style={{ ...pBtn, marginBottom: '10px' }} onClick={handleCopyRecovery}>
              <span>{copied ? 'Copied ✓' : 'Copy to clipboard'}</span>
            </button>
            <button className="cavos-primary-btn" style={{ width: '100%', padding: '12px', borderRadius: `${btnRadius}px`, border: 'none', background: primaryColor, color: '#fff', fontSize: '14px', fontWeight: 500, cursor: 'pointer', fontFamily: 'inherit', transition: 'opacity 0.15s' }} onClick={finishSecureStep}>
              I've saved it
            </button>
          </div>
          {renderFooter()}
        </div>
      </div>
    );
  }

  // ── Passkey approval (returning user, new device, passkey enrolled) ───────

  if (screen === 'passkey-approval') {
    return (
      <div style={overlay} data-cavos-theme={theme} role="dialog" aria-modal>
        <div style={{ ...card, position: 'relative' }}>
          {isMobile && <div style={handle} />}
          <button className="cavos-close" style={close} onClick={handleClose} aria-label="Close"><CloseX /></button>
          <div style={{ padding: isMobile ? '28px 24px 32px' : '48px 24px 32px', textAlign: 'center' }}>
            <BrandBadge><BrandFingerprint /></BrandBadge>
            <h2 style={{ margin: '0 0 8px', fontSize: '17px', fontWeight: 600, color: textColor, letterSpacing: '-0.02em' }}>
              Verify it's you
            </h2>
            <p style={{ margin: '0 0 20px', fontSize: '13px', color: subTextColor, lineHeight: 1.55 }}>
              Confirm with Face ID, Touch ID, or your device PIN to add this device to your account.
            </p>
            {pkError && <div style={{ background: errBg, border: `1px solid ${errBorder}`, borderRadius: '10px', padding: '9px 13px', fontSize: '13px', color: errColor, marginBottom: '14px' }}>{pkError}</div>}
            <button className="cavos-primary-btn" style={{ width: '100%', padding: '12px', borderRadius: `${btnRadius}px`, border: 'none', background: primaryColor, color: '#fff', fontSize: '14px', fontWeight: 500, cursor: pkBusy ? 'default' : 'pointer', fontFamily: 'inherit', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', opacity: pkBusy ? 0.65 : 1 }} onClick={handlePasskeyApprove} disabled={pkBusy}>
              {pkBusy && <Spinner size={15} color="#fff" />}
              {pkBusy ? 'Verifying…' : 'Continue with passkey'}
            </button>
            {walletStatus.awaitingApproval && (
              <button className="cavos-sub-btn" style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '13px', color: subTextColor, width: '100%', textAlign: 'center', padding: '16px 0 0', fontFamily: 'inherit', transition: 'color 0.15s' }} onClick={() => { setScreen('device-approval'); setPkError(''); }}>
                Approve by email instead
              </button>
            )}
            <button className="cavos-sub-btn" style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '13px', color: subTextColor, width: '100%', textAlign: 'center', padding: `${walletStatus.awaitingApproval ? '10px' : '16px'} 0 0`, fontFamily: 'inherit', transition: 'color 0.15s' }} onClick={() => { setScreen('recover'); setPkError(''); }}>
              Use a recovery phrase
            </button>
          </div>
          {renderFooter()}
        </div>
      </div>
    );
  }

  if (screen === 'device-approval') {
    // The provider nulls pendingRequestId when the request expires (while the
    // device is still awaiting approval) — that's our signal to switch copy.
    const expired = walletStatus.awaitingApproval && !walletStatus.pendingRequestId;
    return (
      <div style={overlay} data-cavos-theme={theme} role="dialog" aria-modal>
        <div style={{ ...card, position: 'relative' }}>
          {isMobile && <div style={handle} />}
          <button className="cavos-close" style={close} onClick={handleClose} aria-label="Close"><CloseX /></button>
          <div style={{ padding: isMobile ? '28px 24px 32px' : '48px 24px 32px', textAlign: 'center' }}>
            <BrandBadge><BrandPhone tone={expired ? '#dc2626' : BRAND} /></BrandBadge>
            <h2 style={{ margin: '0 0 8px', fontSize: '17px', fontWeight: 600, color: textColor, letterSpacing: '-0.02em' }}>
              {expired ? 'Approval link expired' : 'Approve this device'}
            </h2>
            <p style={{ margin: '0 0 20px', fontSize: '13px', color: subTextColor, lineHeight: 1.55 }}>
              {expired
                ? 'The approval link is no longer valid. Request a new one below.'
                : <>For your security, we sent an email to approve this device.{appName ? <> Open it on a device where you're already signed in to your {appName} account.</> : null}</>}
            </p>
            {error && <div style={{ background: errBg, border: `1px solid ${errBorder}`, borderRadius: '10px', padding: '9px 13px', fontSize: '13px', color: errColor, marginBottom: '14px' }}>{error}</div>}
            {expired ? (
              <button className="cavos-primary-btn" style={{ width: '100%', padding: '12px', borderRadius: `${btnRadius}px`, border: 'none', background: primaryColor, color: '#fff', fontSize: '14px', fontWeight: 500, cursor: 'pointer', fontFamily: 'inherit', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', opacity: deviceResendBusy ? 0.65 : 1 }} onClick={handleDeviceResend} disabled={deviceResendBusy}>
                {deviceResendBusy && <Spinner size={15} color="#fff" />}
                {deviceResendBusy ? 'Sending…' : 'Request a new link'}
              </button>
            ) : (
              <div style={{ background: isLight ? 'rgba(0,0,0,0.03)' : 'rgba(255,255,255,0.04)', border: `1px solid ${isLight ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.06)'}`, borderRadius: `${btnRadius}px`, padding: '14px 16px', display: 'flex', alignItems: 'center', gap: 10, justifyContent: 'center', marginBottom: '14px' }}>
                <Spinner size={14} color={subTextColor} />
                <span style={{ fontSize: '12px', color: subTextColor }}>Waiting for approval…</span>
              </div>
            )}
            {!expired && (
              <button className="cavos-sub-btn" style={{ background: 'none', border: 'none', cursor: resendCountdown > 0 ? 'default' : 'pointer', fontSize: '13px', color: subTextColor, width: '100%', textAlign: 'center', padding: 0, fontFamily: 'inherit', transition: 'color 0.15s', opacity: resendCountdown > 0 ? 0.6 : 1 }} onClick={handleDeviceResend} disabled={resendCountdown > 0 || deviceResendBusy}>
                {resendCountdown > 0 ? `Resend email in ${resendCountdown}s` : 'Resend approval email'}
              </button>
            )}
            <button className="cavos-sub-btn" style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '13px', color: subTextColor, width: '100%', textAlign: 'center', padding: '14px 0 0', fontFamily: 'inherit', transition: 'color 0.15s' }} onClick={() => { setScreen('recover'); setError(''); }}>
              Sign in with recovery phrase instead
            </button>
          </div>
          {renderFooter()}
        </div>
      </div>
    );
  }

  // ── Recover (lost all devices — restore access with the recovery code) ────

  const handleRecoverSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!recoverCode.trim()) return;
    setRecoverBusy(true);
    setError('');
    try {
      await recover(recoverCode);
      // The provider flips to ready; the existing effect drives triggerDone.
      setScreen('deploying');
      setDeployState('loading');
    } catch (e2) {
      setError(e2 instanceof Error ? e2.message : 'Sign-in failed. Check your recovery phrase and try again.');
      setRecoverBusy(false);
    }
  };

  if (screen === 'recover') {
    return (
      <div style={overlay} data-cavos-theme={theme} role="dialog" aria-modal onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
        <div style={{ ...card, position: 'relative' }}>
          {isMobile && <div style={handle} />}
          <button className="cavos-close" style={{ ...close, left: '16px', right: 'auto' }} onClick={() => { setScreen(walletStatus.hasPasskey && passkeySupported ? 'passkey-approval' : 'device-approval'); setError(''); setRecoverCode(''); }} aria-label="Back">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M19 12H5M12 5l-7 7 7 7"/></svg>
          </button>
          <button className="cavos-close" style={close} onClick={handleClose} aria-label="Close"><CloseX /></button>
          <div style={{ padding: isMobile ? '28px 22px 32px' : '52px 22px 22px' }}>
            <BrandBadge><BrandKey /></BrandBadge>
            <h2 style={{ margin: '0 0 6px', fontSize: '17px', fontWeight: 600, color: textColor, letterSpacing: '-0.02em', textAlign: 'center' }}>Sign in with recovery phrase</h2>
            <p style={{ margin: '0 0 20px', fontSize: '13px', color: subTextColor, textAlign: 'center', lineHeight: 1.5 }}>
              Enter the recovery phrase you saved when you set up this account.
            </p>
            {error && <div style={{ background: errBg, border: `1px solid ${errBorder}`, borderRadius: '10px', padding: '10px 14px', fontSize: '13px', color: errColor, marginBottom: '14px' }}>{error}</div>}
            <form onSubmit={handleRecoverSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              <textarea
                className="cavos-input-inner"
                style={{ width: '100%', padding: '12px 14px', border: inputBorder, borderRadius: `${btnRadius}px`, fontSize: '14px', color: textColor, background: inputBg, fontFamily: 'inherit', boxSizing: 'border-box', resize: 'vertical', minHeight: 72, lineHeight: 1.5 }}
                placeholder="Enter your recovery phrase"
                value={recoverCode}
                onChange={e => setRecoverCode(e.target.value)}
                required
                disabled={recoverBusy}
                autoFocus
              />
              <button type="submit" className="cavos-primary-btn" style={{ width: '100%', padding: '12px', marginTop: '4px', borderRadius: `${btnRadius}px`, border: 'none', background: primaryColor, color: '#fff', fontSize: '14px', fontWeight: 500, cursor: 'pointer', fontFamily: 'inherit', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', transition: 'opacity 0.15s, transform 0.1s', opacity: recoverBusy ? 0.65 : 1 }} disabled={recoverBusy}>
                {recoverBusy && <Spinner size={15} color="#fff" />}
                {recoverBusy ? 'Restoring access…' : 'Restore access'}
              </button>
            </form>
          </div>
          {renderFooter()}
        </div>
      </div>
    );
  }

  // ── Deploying ─────────────────────────────────────────────────────────────

  if (screen === 'deploying') {
    const isDone = deployState === 'done';
    return (
      <div style={overlay} data-cavos-theme={theme} role="dialog" aria-modal>
        <div style={card}>
          {isMobile && <div style={handle} />}
          <div style={{ padding: '52px 28px 44px', display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center', gap: '16px' }}>
            {isDone ? (
              <div className="cavos-check-circle" style={{ width: 64, height: 64, borderRadius: '50%', background: 'rgba(34,197,94,0.12)', border: '1.5px solid rgba(34,197,94,0.35)', display: 'flex', alignItems: 'center', justifyContent: 'center', animation: 'cavos-ring-glow 1.5s ease-out' }}>
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
                  <polyline className="cavos-check-path" points="20 6 9 17 4 12" stroke="#22c55e" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </div>
            ) : (
              <div style={{ width: 64, height: 64, borderRadius: '50%', background: isLight ? 'rgba(0,0,0,0.04)' : 'rgba(255,255,255,0.04)', border: `1.5px solid ${isLight ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.08)'}`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                <Spinner size={26} color={isLight ? 'rgba(0,0,0,0.4)' : 'rgba(255,255,255,0.6)'} />
              </div>
            )}
            <div>
              <h2 style={{ margin: 0, fontSize: '17px', fontWeight: 600, color: textColor, letterSpacing: '-0.02em' }}>
                {isDone ? "You're all set" : 'Setting up your account'}
              </h2>
              <p style={{ margin: '6px 0 0', fontSize: '13px', color: subTextColor }}>
                {isDone
                  ? 'Your account is ready'
                  : deploySlow
                    ? 'This is taking longer than usual — the network may be slow.'
                    : 'This only takes a moment…'}
              </p>
            </div>
            {!isDone && deploySlow && (
              <button
                className="cavos-sub-btn"
                style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '13px', fontWeight: 500, color: primaryColor, padding: '4px 0 0', fontFamily: 'inherit', transition: 'opacity 0.15s' }}
                onClick={() => {
                  if (closeTimerRef.current) clearTimeout(closeTimerRef.current);
                  doneHandledRef.current = false;
                  secureHandledRef.current = false;
                  setDeploySlow(false);
                  setDeployState('loading');
                  setBusy(false);
                  setError('');
                  setScreen('select');
                }}
              >
                Start over
              </button>
            )}
          </div>
          {renderFooter()}
        </div>
      </div>
    );
  }

  // ── Check your inbox ───────────────────────────────────────────────────────

  if (screen === 'verify') {
    return (
      <div style={overlay} data-cavos-theme={theme} role="dialog" aria-modal onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
        <div style={{ ...card, position: 'relative' }}>
          {isMobile && <div style={handle} />}
          <button className="cavos-close" style={close} onClick={handleClose} aria-label="Close"><CloseX /></button>
          <div style={{ padding: isMobile ? '28px 24px 32px' : '40px 24px 24px', textAlign: 'center' }}>
            <div style={{ width: 48, height: 48, borderRadius: '50%', margin: '0 auto 16px', background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.18)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#22c55e" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"/>
              </svg>
            </div>
            <h2 style={{ margin: '0 0 8px', fontSize: '17px', fontWeight: 600, color: textColor, letterSpacing: '-0.02em' }}>Check your inbox</h2>
            <p style={{ margin: '0 0 22px', fontSize: '13px', color: subTextColor, lineHeight: 1.55 }}>
              We sent a sign-in link to <strong style={{ color: textColor, fontWeight: 500 }}>{email}</strong>.<br />Open it on this device to continue.
            </p>
            {error && <div style={{ background: errBg, border: `1px solid ${errBorder}`, borderRadius: '10px', padding: '9px 13px', fontSize: '13px', color: errColor, marginBottom: '14px' }}>{error}</div>}
            <button className="cavos-primary-btn" style={{ width: '100%', padding: '12px', borderRadius: `${btnRadius}px`, border: 'none', background: resendCountdown > 0 ? (isLight ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.08)') : primaryColor, color: resendCountdown > 0 ? subTextColor : '#fff', fontSize: '14px', fontWeight: 500, cursor: resendCountdown > 0 ? 'default' : 'pointer', fontFamily: 'inherit', transition: 'opacity 0.15s', marginBottom: '8px' }} onClick={handleResend} disabled={resendCountdown > 0}>
              {resendCountdown > 0 ? `Resend in ${resendCountdown}s` : 'Resend link'}
            </button>
            <button className="cavos-sub-btn" style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '13px', color: subTextColor, width: '100%', textAlign: 'center', padding: '8px 0 0', fontFamily: 'inherit', transition: 'color 0.15s' }} onClick={() => { setScreen('magic-link'); setError(''); }}>
              Use a different email
            </button>
          </div>
          {renderFooter()}
        </div>
      </div>
    );
  }

  // ── OTP code entry ─────────────────────────────────────────────────────────

  if (screen === 'otp-code') {
    return (
      <div style={overlay} data-cavos-theme={theme} role="dialog" aria-modal onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
        <div style={{ ...card, position: 'relative' }}>
          {isMobile && <div style={handle} />}
          <button className="cavos-close" style={{ ...close, left: '16px', right: 'auto' }} onClick={() => { setScreen('magic-link'); setError(''); setOtpCode(''); }} aria-label="Back">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M19 12H5M12 5l-7 7 7 7"/></svg>
          </button>
          <button className="cavos-close" style={close} onClick={handleClose} aria-label="Close"><CloseX /></button>
          <div style={{ padding: isMobile ? '28px 22px 32px' : '52px 22px 22px', textAlign: 'center' }}>
            <h2 style={{ margin: '0 0 8px', fontSize: '17px', fontWeight: 600, color: textColor, letterSpacing: '-0.02em' }}>Enter your code</h2>
            <p style={{ margin: '0 0 20px', fontSize: '13px', color: subTextColor, lineHeight: 1.5 }}>
              We sent a 6-digit code to <strong style={{ color: textColor, fontWeight: 500 }}>{email}</strong>.
            </p>
            {error && <div style={{ background: errBg, border: `1px solid ${errBorder}`, borderRadius: '10px', padding: '10px 14px', fontSize: '13px', color: errColor, marginBottom: '14px', textAlign: 'left' }}>{error}</div>}
            <form onSubmit={handleOtpVerifySubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              <div style={{ display: 'flex', gap: '8px', justifyContent: 'center' }} onPaste={onOtpPaste}>
                {[0, 1, 2, 3, 4, 5].map(i => (
                  <input
                    key={i}
                    ref={el => { otpBoxRefs.current[i] = el; }}
                    className={`cavos-input-inner cavos-otp-box ${otpCode[i] ? 'cavos-otp-box-filled' : ''}`}
                    style={{
                      width: '44px',
                      height: '52px',
                      padding: 0,
                      border: inputBorder,
                      borderRadius: `${btnRadius}px`,
                      fontSize: '22px',
                      fontWeight: 600,
                      color: textColor,
                      background: inputBg,
                      fontFamily: 'inherit',
                      boxSizing: 'border-box',
                      textAlign: 'center',
                    }}
                    type="text"
                    inputMode="numeric"
                    autoComplete={i === 0 ? 'one-time-code' : 'off'}
                    maxLength={1}
                    value={otpCode[i] ?? ''}
                    onChange={e => setOtpDigit(i, e.target.value)}
                    onKeyDown={e => onOtpKeyDown(i, e)}
                    onFocus={e => e.target.select()}
                    disabled={busy}
                    autoFocus={i === 0}
                  />
                ))}
              </div>
              <button type="submit" className="cavos-primary-btn" style={{ width: '100%', padding: '12px', marginTop: '4px', borderRadius: `${btnRadius}px`, border: 'none', background: primaryColor, color: '#fff', fontSize: '14px', fontWeight: 500, cursor: 'pointer', fontFamily: 'inherit', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', transition: 'opacity 0.15s, transform 0.1s', opacity: busy || otpCode.length !== 6 ? 0.65 : 1 }} disabled={busy || otpCode.length !== 6}>
                {busy && <Spinner size={15} color="#fff" />}
                {busy ? 'Verifying…' : 'Continue'}
              </button>
            </form>
            <button className="cavos-primary-btn" style={{ width: '100%', padding: '12px', borderRadius: `${btnRadius}px`, border: 'none', background: resendCountdown > 0 ? (isLight ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.08)') : 'transparent', color: resendCountdown > 0 ? subTextColor : primaryColor, fontSize: '14px', fontWeight: 500, cursor: resendCountdown > 0 ? 'default' : 'pointer', fontFamily: 'inherit', transition: 'opacity 0.15s', marginTop: '8px' }} onClick={handleResend} disabled={resendCountdown > 0 || busy}>
              {resendCountdown > 0 ? `Resend in ${resendCountdown}s` : 'Resend code'}
            </button>
            <button className="cavos-sub-btn" style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: '13px', color: subTextColor, width: '100%', textAlign: 'center', padding: '8px 0 0', fontFamily: 'inherit', transition: 'color 0.15s' }} onClick={() => { setScreen('magic-link'); setError(''); setOtpCode(''); }}>
              Use a different email
            </button>
          </div>
          {renderFooter()}
        </div>
      </div>
    );
  }

  // ── Email form ─────────────────────────────────────────────────────────────

  if (screen === 'magic-link') {
    const isOtp = emailMode === 'otp';
    return (
      <div style={overlay} data-cavos-theme={theme} role="dialog" aria-modal onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
        <div style={{ ...card, position: 'relative' }}>
          {isMobile && <div style={handle} />}
          <button className="cavos-close" style={{ ...close, left: '16px', right: 'auto' }} onClick={() => { setScreen('select'); setError(''); }} aria-label="Back">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M19 12H5M12 5l-7 7 7 7"/></svg>
          </button>
          <button className="cavos-close" style={close} onClick={handleClose} aria-label="Close"><CloseX /></button>
          <div style={{ padding: isMobile ? '28px 22px 32px' : '52px 22px 22px' }}>
            <h2 style={{ margin: '0 0 6px', fontSize: '17px', fontWeight: 600, color: textColor, letterSpacing: '-0.02em', textAlign: 'center' }}>Sign in with email</h2>
            <p style={{ margin: '0 0 20px', fontSize: '13px', color: subTextColor, textAlign: 'center', lineHeight: 1.5 }}>
              {isOtp ? "We'll send a secure sign-in code to your inbox." : "We'll send a secure sign-in link to your inbox."}
            </p>
            {error && <div style={{ background: errBg, border: `1px solid ${errBorder}`, borderRadius: '10px', padding: '10px 14px', fontSize: '13px', color: errColor, marginBottom: '14px' }}>{error}</div>}
            <form onSubmit={isOtp ? handleOtpRequestSubmit : handleMagicLinkSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              <input className="cavos-input-inner" style={{ width: '100%', padding: '12px 14px', border: inputBorder, borderRadius: `${btnRadius}px`, fontSize: '14px', color: textColor, background: inputBg, fontFamily: 'inherit', boxSizing: 'border-box', transition: 'border-color 0.15s' }} type="email" placeholder="your@email.com" value={email} onChange={e => setEmail(e.target.value)} required disabled={busy} autoFocus />
              <button type="submit" className="cavos-primary-btn" style={{ width: '100%', padding: '12px', marginTop: '4px', borderRadius: `${btnRadius}px`, border: 'none', background: primaryColor, color: '#fff', fontSize: '14px', fontWeight: 500, cursor: 'pointer', fontFamily: 'inherit', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '8px', transition: 'opacity 0.15s, transform 0.1s', opacity: busy ? 0.65 : 1 }} disabled={busy}>
                {busy && <Spinner size={15} color="#fff" />}
                {busy ? 'Sending…' : (isOtp ? 'Send code' : 'Send magic link')}
              </button>
            </form>
          </div>
          {renderFooter()}
        </div>
      </div>
    );
  }

  // ── Provider selection ─────────────────────────────────────────────────────

  const showEmail = providers.includes('email');
  const showGoogle = providers.includes('google');
  const showApple = providers.includes('apple');
  const hasSocial = showGoogle || showApple;
  // Absolute-positioned icon so the label stays optically centered (matches the
  // Privy/Clerk full-width button look) instead of shifting when text changes.
  // No background box — the brand logos render clean, like native sign-in buttons.
  const btnIcon = (icon: React.ReactNode, busyIcon: React.ReactNode, color: string) => (
    <span style={{ position: 'absolute', left: '16px', width: 20, height: 20, display: 'flex', alignItems: 'center', justifyContent: 'center', color, flexShrink: 0, transition: 'color 0.25s ease' }}>
      {busy ? busyIcon : icon}
    </span>
  );

  return (
    <div style={overlay} data-cavos-theme={theme} role="dialog" aria-modal onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
      <div style={{ ...card, position: 'relative' }}>
        {isMobile && <div style={handle} />}
        <button className="cavos-close" style={close} onClick={handleClose} aria-label="Close"><CloseX /></button>

        <div style={{ padding: isMobile ? '24px 20px 32px' : '40px 24px 24px' }}>
          <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '16px' }}>
            {appLogo ? (
              <img
                src={appLogo}
                alt={appName || 'Logo'}
                decoding="async"
                fetchPriority="high"
                style={{ display: 'block', height: `${appLogoSize ?? 40}px`, minHeight: `${appLogoSize ?? 40}px`, width: 'auto', maxWidth: `${(appLogoSize ?? 40) * 4}px`, objectFit: 'contain' }}
              />
            ) : (
              // Default brand mark: the Cavos star, inheriting the theme text
              // color so it stays visible on light and dark backgrounds.
              <span style={{ color: textColor, display: 'flex' }}>
                <CavosStar size={appLogoSize ?? 34} />
              </span>
            )}
          </div>
          <h2 style={{ margin: '0 0 22px', fontSize: '17px', fontWeight: 600, color: textColor, letterSpacing: '-0.02em', textAlign: 'center' }}>
            {appName ? `Sign in to ${appName}` : 'Sign in or sign up'}
          </h2>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {showGoogle && (
              <button className="cavos-provider" style={{ ...pBtn, ...(busy ? { opacity: 0.55, cursor: 'not-allowed' } : {}) }} onClick={() => handleOAuth('google')} disabled={busy}>
                {btnIcon(<GoogleIcon />, <Spinner size={14} color="#888" />, '#4285F4')}
                <span>Continue with Google</span>
              </button>
            )}

            {showApple && (
              <button className="cavos-provider" style={{ ...pBtn, ...(busy ? { opacity: 0.55, cursor: 'not-allowed' } : {}) }} onClick={() => handleOAuth('apple')} disabled={busy}>
                {btnIcon(<AppleIcon />, <Spinner size={14} color={isLight ? '#111' : '#fff'} />, isLight ? '#111' : '#fff')}
                <span>Continue with Apple</span>
              </button>
            )}

            {showEmail && hasSocial && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px', margin: '6px 0 2px' }}>
                <span className="cavos-divider-line" style={{ background: isLight ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.08)' }} />
                <span style={{ fontSize: '12px', color: subTextColor, textTransform: 'uppercase', letterSpacing: '0.05em' }}>or</span>
                <span className="cavos-divider-line" style={{ background: isLight ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.08)' }} />
              </div>
            )}

            {showEmail && (
              <button className="cavos-provider" style={{ ...pBtn, cursor: busy ? 'not-allowed' : 'pointer' }} onClick={() => setScreen('magic-link')} disabled={busy}>
                {btnIcon(<EmailIcon />, <Spinner size={14} color={primaryColor} />, primaryColor)}
                <span>Continue with email</span>
              </button>
            )}
          </div>

          {error && <div style={{ marginTop: '14px', background: errBg, border: `1px solid ${errBorder}`, borderRadius: '10px', padding: '9px 13px', fontSize: '13px', color: errColor }}>{error}</div>}

          <p style={{ margin: '18px 0 0', fontSize: '11px', color: subTextColor, textAlign: 'center', lineHeight: 1.55 }}>
            By continuing you agree to the{' '}
            <a href="https://cavos.xyz/user-privacy" target="_blank" rel="noopener noreferrer" style={{ color: isLight ? 'rgba(0,0,0,0.45)' : 'rgba(255,255,255,0.45)', textDecoration: 'underline' }}>Privacy Policy</a>
{' & '}
            <a href="https://cavos.xyz/user-terms" target="_blank" rel="noopener noreferrer" style={{ color: isLight ? 'rgba(0,0,0,0.45)' : 'rgba(255,255,255,0.45)', textDecoration: 'underline' }}>Terms</a>.
          </p>
        </div>

        {renderFooter()}
      </div>
    </div>
  );
}

// ─── useCavosAuth hook ────────────────────────────────────────────────────────

export function useCavosAuth() {
  const { openModal, closeModal, isAuthenticated, address, user, walletStatus, logout } = useCavos();
  return { openModal, closeModal, isAuthenticated, address, user, walletStatus, logout };
}
