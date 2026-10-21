// Terminal appearance presets. Selection is stored in localStorage and read
// by TerminalPane at creation.
export const TERM_THEMES = {
  dark: {
    label: 'Sloth dark',
    theme: {
      background: '#0a0d10',
      foreground: '#d6dde5',
      cursor: '#34d399',
      cursorAccent: '#0a0d10',
      selectionBackground: '#33455c',
    },
  },
  midnight: {
    label: 'Midnight (true black)',
    theme: {
      background: '#000000',
      foreground: '#c9d1d9',
      cursor: '#58a6ff',
      cursorAccent: '#000000',
      selectionBackground: '#264f78',
    },
  },
  solarized: {
    label: 'Solarized dark',
    theme: {
      background: '#002b36',
      foreground: '#839496',
      cursor: '#b58900',
      cursorAccent: '#002b36',
      selectionBackground: '#073642',
    },
  },
  paper: {
    label: 'Paper (light)',
    theme: {
      background: '#f8f7f4',
      foreground: '#1c1917',
      cursor: '#059669',
      cursorAccent: '#f8f7f4',
      selectionBackground: '#a7f3d0',
    },
  },
};

export function termOptions() {
  return {
    fontSize: parseInt(localStorage.getItem('ssloth.termFontSize') || '13', 10),
    theme: TERM_THEMES[localStorage.getItem('ssloth.termTheme')]?.theme || TERM_THEMES.dark.theme,
  };
}
