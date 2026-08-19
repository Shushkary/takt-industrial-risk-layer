// Дизайн-токены TAKT АРМ — строгий кибербез / SOC-консоль.
// Холодная почти-чёрная база, острые углы, моноширинные данные, тактические LED-акценты.

export const theme = {
  colors: {
    // Холодные технические поверхности (slate/graphite), а не тёплый Apple-grey.
    background: '#070a0f',
    surface: '#0d1219',
    surfaceElevated: '#131a24',
    surfaceHover: '#1a2331',
    border: '#20293a',
    borderStrong: '#2c3852',
    grid: '#111826',

    // Текст
    textPrimary: '#e6edf6',
    textSecondary: '#9fb0c6',
    textMuted: '#61708a',

    // Тактические уровни серьёзности (высокая читаемость на тёмном, WCAG AA).
    critical: '#ff3b52',
    high: '#ff8f1f',
    medium: '#ffd23f',
    low: '#39a0ff',

    // Акценты
    accent: '#22d3ee',      // терминальный циан — основной операционный акцент
    accentHover: '#5ee7f5',
    focus: '#22d3ee',
    success: '#2ee66f',     // «в сети» / подтверждение
    warning: '#ffb020',
    error: '#ff3b52',

    // Состояния кейса
    new: '#39a0ff',
    investigating: '#ffd23f',
    resolved: '#2ee66f',
  },

  spacing: {
    xs: '4px',
    sm: '8px',
    md: '16px',
    lg: '24px',
    xl: '32px',
  },

  borderRadius: {
    sm: '4px',
    md: '6px',
    lg: '8px',
    xl: '10px',
  },

  transitions: {
    fast: '120ms cubic-bezier(0.2, 0.7, 0.2, 1)',
    normal: '200ms cubic-bezier(0.2, 0.7, 0.2, 1)',
    slow: '320ms cubic-bezier(0.2, 0.7, 0.2, 1)',
  },

  typography: {
    fontFamily: '"Inter", "SF Pro Text", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    fontMono: '"JetBrains Mono", "SFMono-Regular", "Cascadia Code", Consolas, "Roboto Mono", monospace',
    fontSize: {
      xs: '11px',
      sm: '13px',
      md: '15px',
      lg: '18px',
      xl: '22px',
    },
  },

  zIndex: {
    base: 0,
    dropdown: 100,
    modal: 200,
    tooltip: 300,
  },
};

// CSS переменные для глобального использования
export const cssVariables = `
:root {
  --color-background: ${theme.colors.background};
  --color-surface: ${theme.colors.surface};
  --color-surface-elevated: ${theme.colors.surfaceElevated};
  --color-surface-hover: ${theme.colors.surfaceHover};
  --color-border: ${theme.colors.border};
  --color-border-strong: ${theme.colors.borderStrong};
  --color-grid: ${theme.colors.grid};

  --color-text-primary: ${theme.colors.textPrimary};
  --color-text-secondary: ${theme.colors.textSecondary};
  --color-text-muted: ${theme.colors.textMuted};

  --color-critical: ${theme.colors.critical};
  --color-high: ${theme.colors.high};
  --color-medium: ${theme.colors.medium};
  --color-low: ${theme.colors.low};

  --color-accent: ${theme.colors.accent};
  --color-accent-hover: ${theme.colors.accentHover};
  --color-focus: ${theme.colors.focus};
  --color-success: ${theme.colors.success};
  --color-warning: ${theme.colors.warning};
  --color-error: ${theme.colors.error};

  --color-new: ${theme.colors.new};
  --color-investigating: ${theme.colors.investigating};
  --color-resolved: ${theme.colors.resolved};

  --font-mono: ${theme.typography.fontMono};

  --transition-fast: ${theme.transitions.fast};
  --transition-normal: ${theme.transitions.normal};
  --transition-slow: ${theme.transitions.slow};
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: ${theme.typography.fontFamily};
  font-size: ${theme.typography.fontSize.md};
  background-color: var(--color-background);
  color: var(--color-text-primary);
  line-height: 1.5;
  color-scheme: dark;
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
}

/* Поддержка prefers-reduced-motion */
@media (prefers-reduced-motion: reduce) {
  * {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
  }
}
`;
