"use client";
import { useState } from "react";

const IOCS = [
  { type: "domain", val: "m1crosoft.com", risk: "ÉLEVÉ" },
  { type: "url", val: "secure-login.m1crosoft.com/verify", risk: "CRITIQUE" },
  { type: "ip", val: "203.0.113.5", risk: "MOYEN" },
  { type: "keyword", val: "urgent / verify", risk: "FAIBLE" },
];

export default function ForensicBoard() {
  const [run, setRun] = useState(false);
  return (
    <div className="board rounded-xl border border-edge p-5">
      <div className="flex items-center justify-between">
        <span className="coord text-amberx">dossier · émail #0421</span>
        <span className="coord text-slate-500">phishing_email.eml</span>
      </div>

      <div className="mt-4 grid gap-4 sm:grid-cols-[1.1fr_0.9fr]">
        {/* email source */}
        <div className="rounded-lg border border-edge bg-slate9 p-4 font-mono text-[11px] leading-relaxed">
          <div className="text-slate-500">$ parse_email('phishing_email.eml')</div>
          <div className="mt-2 space-y-0.5">
            <div><span className="text-teal">From:</span> security@m1crosoft.com</div>
            <div><span className="text-teal">Subject:</span> Urgent: Suspicious Login</div>
            <div><span className="text-teal">Received:</span> from [203.0.113.5]</div>
            <div className="mt-2 text-slate-400">... verify your account immediately:</div>
            <div className={run ? "ioc mt-1 text-amberx" : "mt-1 text-slate-400"}>http://secure-login.m1crosoft.com/verify</div>
          </div>
        </div>

        {/* risk score ring */}
        <div className="flex flex-col items-center justify-center rounded-lg border border-edge bg-slate9 p-4">
          <svg width="120" height="120" viewBox="0 0 120 120">
            <circle className="ring-bg" cx="60" cy="60" r="48" fill="none" strokeWidth="9" />
            <circle className="ring-fg" cx="60" cy="60" r="48" fill="none" strokeWidth="9"
              strokeDasharray="302" strokeDashoffset={run ? 105 : 302} transform="rotate(-90 60 60)" />
          </svg>
          <div className="-mt-16 text-center">
            <div className="font-display text-3xl font-extrabold text-amberx">{run ? 65 : "--"}</div>
            <div className="coord text-slate-500">/ 100 · Élevé</div>
          </div>
          <div className="mt-12 coord text-slate-500">{run ? "9 IOCs détectés" : "en attente"}</div>
        </div>
      </div>

      {/* IOC findings */}
      <div className="mt-4 space-y-2">
        {IOCS.map((x,i)=>(
          <div key={x.type} className={`rounded-r ${run ? "ioc" : "border-l-2 border-edge bg-white/[.02]"} px-3 py-2 font-mono text-[11px]`}>
            <span className="mr-2 text-slate-500">0{i+1}</span>
            <span className="text-teal">{x.type}</span>
            <span className="mx-2 text-slate-300">{x.val}</span>
            <span className={run ? "float-right text-amberx" : "float-right text-slate-600"}>{run ? x.risk : "—"}</span>
          </div>
        ))}
      </div>

      <button onClick={()=>setRun(!run)} className="mt-5 w-full rounded-lg bg-amberx px-5 py-2.5 font-mono text-xs font-bold uppercase tracking-widest text-slate9 transition hover:bg-white">
        {run ? "↺ Réinitialiser" : "▶ Analyser l'email"}
      </button>
    </div>
  );
}
