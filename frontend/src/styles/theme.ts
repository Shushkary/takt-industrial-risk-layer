// Дизайн-токены TAKT АРМ — тёмная тема SOC-стандарт

export const theme = {
  colors: {
    // Основные цвета
    background: '#1a1a1a',
    surface: '#2a2a2a',
    surfaceHover: '#3a3a3a',
    border: '#404040',
    
    // Текст
    textPrimary: '#ffffff',
    textSecondary: '#b0b0b0',
    textMuted: '#808080',
    
    // Severity levels (WCAG 2.1 AA контрастность ≥ 4.5:1)
    critical: '#ff4444',
    high: '#ff9944',
    medium: '#ffcc44',
    low: '#4488ff',
    
    // Акценты
    accent: '#00aaff',
    accentHover: '#0099ee',
    success: '#44ff88',
    warning: '#ffaa44',
    error: '#ff4444',
    
    // Состояния
    new: '#4488ff',
    investigating: '#ffcc44',
    resolved: '#44ff88',
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
    md: '8px',
    lg: '12px',
  },
  
  transitions: {
    fast: '150ms ease',
    normal: '300ms ease',
    slow: '500ms ease',
  },
  
  typography: {
    fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif',
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
