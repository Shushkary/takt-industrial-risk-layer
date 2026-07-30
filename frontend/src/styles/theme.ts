// Дизайн-токены TAKT АРМ — тёмная тема SOC-стандарт

export const theme = {
  colors: {
    // Apple-style base/elevated dark surfaces.
    background: '#000000',
    surface: '#1c1c1e',
    surfaceElevated: '#2c2c2e',
    surfaceHover: '#3a3a3c',
    border: '#38383a',
    
    // Текст
    textPrimary: '#f5f5f7',
    textSecondary: '#c7c7cc',
    textMuted: '#8e8e93',
    
    // Apple system colors adapted for dark appearance.
    critical: '#ff453a',
    high: '#ff9f0a',
    medium: '#ffd60a',
    low: '#64d2ff',
    
    // Акценты
    accent: '#0a84ff',
    accentHover: '#409cff',
    focus: '#64d2ff',
    success: '#30d158',
    warning: '#ff9f0a',
    error: '#ff453a',
    
    // Состояния
    new: '#0a84ff',
    investigating: '#ffd60a',
    resolved: '#30d158',
  },
  
  spacing: {
    xs: '4px',
    sm: '8px',
    md: '16px',
    lg: '24px',
    xl: '32px',
  },
  
  borderRadius: {
    sm: '8px',
    md: '12px',
    lg: '16px',
    xl: '22px',
  },
  
  transitions: {
    fast: '160ms cubic-bezier(0.2, 0.8, 0.2, 1)',
    normal: '280ms cubic-bezier(0.2, 0.8, 0.2, 1)',
    slow: '450ms cubic-bezier(0.2, 0.8, 0.2, 1)',
  },
  
  typography: {
    fontFamily: '"SF Pro Display", "SF Pro Text", -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif',
    fontSize: {
      xs: '12px',
      sm: '14px',
      md: '16px',
      lg: '18px',
      xl: '24px',
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
