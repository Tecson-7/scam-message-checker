import { useState } from 'react'
import { checkMessage } from './api.js'
import { EXAMPLES, LANGUAGES, STRINGS } from './i18n.js'
import About from './components/About.jsx'
import Result from './components/Result.jsx'

const MAX_CHARS = 2000

export default function App() {
  const [lang, setLang] = useState('en')
  const [tab, setTab] = useState('check')
  const [text, setText] = useState('')
  const [checkedText, setCheckedText] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const t = STRINGS[lang]

  async function runCheck(message, language) {
    if (!message.trim()) {
      setError(STRINGS[language].emptyError)
      return
    }
    setLoading(true)
    setError('')
    try {
      const data = await checkMessage(message, language)
      setResult(data)
      setCheckedText(message)
    } catch (e) {
      setError(e instanceof TypeError ? STRINGS[language].error : e.message)
    } finally {
      setLoading(false)
    }
  }

  function changeLanguage(code) {
    setLang(code)
    // re-check so the AI explanation comes back in the new language
    if (result && !loading) runCheck(checkedText, code)
  }

  function loadExample(kind) {
    setText(EXAMPLES[kind])
    setResult(null)
    setError('')
  }

  return (
    <div className="app" lang={lang}>
      <header className="header">
        <div className="brand">
          <img src="/favicon.svg" alt="" width="32" height="32" />
          <h1>{t.title}</h1>
        </div>
        <div className="lang" role="group" aria-label={t.languageLabel}>
          {LANGUAGES.map((l) => (
            <button key={l.code} className={l.code === lang ? 'active' : ''} onClick={() => changeLanguage(l.code)}
                    aria-pressed={l.code === lang}>
              {l.label}
            </button>
          ))}
        </div>
      </header>

      <nav className="tabs">
        <button className={tab === 'check' ? 'active' : ''} onClick={() => setTab('check')}>{t.tabCheck}</button>
        <button className={tab === 'about' ? 'active' : ''} onClick={() => setTab('about')}>{t.tabAbout}</button>
      </nav>

      <main>
        {tab === 'about' ? <About /> : (
          <>
            <section className="card input-card">
              <p className="tagline">{t.tagline}</p>
              <textarea
                value={text}
                onChange={(e) => setText(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) runCheck(text, lang) }}
                placeholder={t.placeholder}
                maxLength={MAX_CHARS}
                rows={6}
                aria-label={t.placeholder}
              />
              <div className="input-row">
                <div className="examples">
                  <button className="ghost" onClick={() => loadExample('scam')}>{t.tryScam}</button>
                  <button className="ghost" onClick={() => loadExample('safe')}>{t.trySafe}</button>
                  {text && <button className="ghost" onClick={() => { setText(''); setResult(null) }}>{t.clear}</button>}
                </div>
                <span className="count">{text.length}/{MAX_CHARS}</span>
              </div>
              <button className="primary" onClick={() => runCheck(text, lang)} disabled={loading}>
                {loading ? <><span className="spinner" aria-hidden="true" />{t.checking}</> : t.check}
              </button>
              {error && <p className="error" role="alert">{error}</p>}
            </section>

            {result && <Result result={result} text={checkedText} t={t} />}
          </>
        )}
      </main>

      <footer className="footer">
        <p>🔒 {t.privacy}</p>
        <p>{t.disclaimer}</p>
      </footer>
    </div>
  )
}
