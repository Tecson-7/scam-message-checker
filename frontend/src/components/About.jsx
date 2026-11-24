export default function About() {
  return (
    <div className="about">
      <section className="card">
        <h3>How it works</h3>
        <p>Every message is checked in three independent ways, then the results are combined:</p>
        <ol>
          <li>
            <strong>Pattern rules</strong> look for common scam tactics — urgency, threats, KYC or
            OTP requests, prizes, easy-money job offers.
          </li>
          <li>
            <strong>Link checks</strong> follow shortened links to where they really go (without
            opening the page), check them against Google Safe Browsing, look up how old the website
            is, and spot fake look-alikes of banks and companies.
          </li>
          <li>
            <strong>AI analysis</strong> (Google Gemini) reads the whole message, names the scam type
            and explains it in simple English, Tamil or Hindi.
          </li>
        </ol>
        <p>
          The AI is not the only judge: its opinion is one of three signals. A link that Google has
          already flagged as dangerous is always treated as a scam.
        </p>
      </section>

      <section className="card">
        <h3>Privacy</h3>
        <p>
          Phone numbers, account and card numbers, UPI IDs, emails and names are masked before
          anything is saved. The original message is never stored.
        </p>
      </section>

      <section className="card">
        <h3>Limitations</h3>
        <ul>
          <li>It can make mistakes — new scam styles may be missed, and unusual genuine messages may be flagged.</li>
          <li>It only looks at the message and its links; it can't verify who actually sent it.</li>
          <li>Domain age isn't available for every website.</li>
        </ul>
      </section>

      <section className="card">
        <h3>Got scammed? Act fast</h3>
        <ul>
          <li>Call the cyber fraud helpline <a href="tel:1930">1930</a> — the sooner, the better the chance of stopping the money.</li>
          <li>Report online at <a href="https://cybercrime.gov.in" target="_blank" rel="noreferrer">cybercrime.gov.in</a>.</li>
          <li>Report fraud SMS and calls on <a href="https://sancharsaathi.gov.in" target="_blank" rel="noreferrer">Sanchar Saathi (Chakshu)</a>.</li>
        </ul>
      </section>
    </div>
  )
}
