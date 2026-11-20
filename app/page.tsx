import ForensicBoard from "@/components/ForensicBoard";
import Reveal from "@/components/Reveal";

const STEPS = [
  ["parse_email", "Parse le .eml : headers, Received, corps, pièces jointes"],
  ["extract_iocs", "Extraction IOCs : domaines, URLs, IPs, mots-clés, fichiers"],
  ["compute_score", "Score 0-100 pondéré par criticité (Critique → Faible)"],
  ["generate_report", "Rapport PDF : IOCs, preuves SHA256, recommandations"],
];

export default function Page() {
  return (
    <main className="board min-h-screen bg-slate9">
      <nav className="sticky top-0 z-40 border-b border-edge bg-slate9/90 backdrop-blur">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-5 py-4">
          <a href="#top" className="flex items-center gap-3"><span className="grid h-9 w-9 place-items-center rounded bg-amberx font-mono text-xs font-bold text-slate9">P7</span><span className="coord text-slate-300">FORENSIC · POST-PHISHING</span></a>
          <div className="hidden gap-7 md:flex">{[["#board","Analyse"],["#pipeline","Pipeline"],["#demo","Démo"],["#ethique","Éthique"]].map(([h,l])=><a key={h} href={h} className="coord text-slate-400 hover:text-amberx">{l}</a>)}</div>
          <a href="https://github.com/LaidiMohammed/aegis-p7-forensique-email" target="_blank" rel="noreferrer" className="rounded border border-edge px-3 py-1.5 font-mono text-[11px] text-slate-300 hover:border-amberx hover:text-amberx">GitHub ↗</a>
        </div>
      </nav>

      <section id="top" className="mx-auto grid max-w-7xl gap-12 px-5 py-16 lg:grid-cols-[1fr_1.05fr] lg:items-center lg:py-20">
        <div>
          <Reveal><div className="mb-5 flex items-center gap-3"><span className="h-px w-12 bg-amberx"/><span className="coord text-amberx">Fiche technique · P7</span></div></Reveal>
          <Reveal delay={70}><h1 className="font-display text-5xl font-extrabold leading-[1.02] sm:text-6xl">Forensique<br/><span className="text-amberx">post-phishing</span></h1></Reveal>
          <Reveal delay={140}><p className="mt-6 max-w-xl text-base leading-relaxed text-slate-400">Analyse d'un email <b className="text-slate-200">.eml</b> : en-têtes Received, IOCs (URLs, IP, typosquatting), pièces jointes et score de risque — puis rapport PDF.</p></Reveal>
          <Reveal delay={210}><div className="mt-8 flex flex-wrap gap-3"><a href="#board" className="rounded bg-amberx px-6 py-3 font-mono text-xs font-bold uppercase tracking-widest text-slate9 hover:bg-white">Analyser ↓</a><a href="#pipeline" className="rounded border border-edge px-6 py-3 font-mono text-xs uppercase tracking-widest text-slate-300 hover:border-amberx">Le pipeline</a></div></Reveal>
          <Reveal delay={280}><div className="mt-10 grid grid-cols-4 gap-4 border-t border-edge pt-6">{[["04","étapes"],["09","IOCs"],["1","rapport PDF"],["00","GPU"]].map(([n,l])=><div key={l}><div className="font-display text-2xl font-extrabold text-white">{n}</div><div className="coord text-slate-500">{l}</div></div>)}</div></Reveal>
        </div>
        <Reveal delay={120}><ForensicBoard /></Reveal>
      </section>

      <section id="pipeline" className="mx-auto max-w-7xl px-5 py-14">
        <Reveal><span className="coord text-amberx">01 / Pipeline</span><h2 className="mt-2 font-display text-4xl font-bold sm:text-5xl">Quatre étapes claires</h2></Reveal>
        <div className="mt-8 grid gap-4 md:grid-cols-2">
          {STEPS.map(([n,d],i)=><Reveal key={n} delay={i*70}><div className="evidence p-5"><div className="flex items-center gap-3"><span className="coord text-amberx">0{i+1}</span><span className="font-mono text-sm text-teal">{n}</span></div><p className="mt-2 text-xs text-slate-400">{d}</p></div></Reveal>)}
        </div>
      </section>

      <section id="demo" className="mx-auto max-w-7xl px-5 py-14">
        <Reveal><span className="coord text-amberx">02 / Démonstration</span><h2 className="mt-2 font-display text-4xl font-bold sm:text-5xl">Commandes</h2></Reveal>
        <div className="mt-8 space-y-2 rounded-xl border border-edge bg-board p-5 text-xs">
          {["python -m src.email_forensics_main --file phishing_email.eml --save-json outputs/results.json --pdf outputs/rapport-p7.pdf","python -m src.generate_report --json outputs/results.json --pdf outputs/rapport-p7.pdf"].map(c=><div key={c} className="rounded border border-edge bg-slate9 px-4 py-3 font-mono text-slate-300"><span className="text-amberx">$</span> {c}</div>)}
        </div>
      </section>

      <section id="ethique" className="mx-auto max-w-7xl px-5 py-14">
        <Reveal><span className="coord text-amberx">03 / Éthique</span><h2 className="mt-2 font-display text-4xl font-bold sm:text-5xl">Données locales</h2></Reveal>
        <div className="mt-6 rounded-xl border-l-2 border-amberx bg-board p-6"><p className="text-sm leading-relaxed text-slate-400">Analyse d'emails de laboratoire (Juice Shop / boîte locale). Les pièces jointes sont hachées (SHA256), jamais exécutées. Anonymisation, 0 GPU, 0 cloud.</p></div>
      </section>

      <footer className="border-t border-edge bg-board">
        <div className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-6 px-5 py-10">
          <div><div className="font-display text-2xl font-extrabold">P7 <span className="text-amberx">/ FORENSIC</span></div><div className="coord mt-1 text-slate-500">Master 1 PFE · Laidi Mohammed · 2026</div></div>
          <div className="flex gap-5 font-mono text-xs text-slate-400"><a href="https://github.com/LaidiMohammed/aegis-p7-forensique-email" target="_blank" rel="noreferrer" className="hover:text-amberx">GitHub ↗</a><a href="https://aegis-p7-forensique-email.vercel.app" className="hover:text-amberx">Vercel ↗</a></div>
        </div>
      </footer>
    </main>
  );
}
