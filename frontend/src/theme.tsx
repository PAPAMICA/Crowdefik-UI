import { createContext, useContext, useEffect, useMemo, useState } from 'react'

type ThemeMode = 'system' | 'light' | 'dark'

type Ctx = {
  mode: ThemeMode
  setMode: (m: ThemeMode) => void
  effective: 'light' | 'dark'
}

const ThemeContext = createContext<Ctx | null>(null)

const STORAGE_KEY = 'crowdefik_theme'

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [mode, setModeState] = useState<ThemeMode>(() => {
    const v = localStorage.getItem(STORAGE_KEY) as ThemeMode | null
    return v === 'light' || v === 'dark' || v === 'system' ? v : 'system'
  })

  const [systemDark, setSystemDark] = useState(() =>
    window.matchMedia?.('(prefers-color-scheme: dark)').matches ? true : false,
  )

  useEffect(() => {
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const on = () => setSystemDark(mq.matches)
    mq.addEventListener?.('change', on)
    return () => mq.removeEventListener?.('change', on)
  }, [])

  const effective: 'light' | 'dark' = mode === 'system' ? (systemDark ? 'dark' : 'light') : mode

  useEffect(() => {
    document.documentElement.classList.toggle('dark', effective === 'dark')
  }, [effective])

  const setMode = (m: ThemeMode) => {
    localStorage.setItem(STORAGE_KEY, m)
    setModeState(m)
  }

  const value = useMemo(() => ({ mode, setMode, effective }), [mode, effective])
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>
}

export function useTheme() {
  const v = useContext(ThemeContext)
  if (!v) throw new Error('useTheme must be used within ThemeProvider')
  return v
}
