export function parseEmail(eml: string) {
  const headers: Record<string, string> = {};
  const lines = eml.split(/\r?\n/);
  let inHeaders = true;
  const body: string[] = [];
  for (const line of lines) {
    if (inHeaders) {
      if (line.trim() === "") { inHeaders = false; continue; }
      const m = line.match(/^([A-Za-z-]+):\s*(.*)$/);
      if (m) headers[m[1].toLowerCase()] = m[2];
    } else body.push(line);
  }
  const sender = headers["from"] || "";
  const subject = headers["subject"] || "";
  const bodyText = body.join("\n");
  const urls = bodyText.match(/https?:\/\/[^\s<>"]+/g) || [];
  const ips = (eml.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []);
  const keywords = ["urgent","verify","suspicious","login","account","password","update","security"].filter(k => bodyText.toLowerCase().includes(k));
  const suspiciousDomains = ["gmai1.com","micr0soft.com","m1crosoft","paypa1.com","faceb00k.com","amaz0n.com"];
  const domain = sender.split("@")[1] || "";
  const typosquat = suspiciousDomains.some(d => domain.includes(d));
  const iocs = [
    ...(typosquat ? [{ type: "domain", value: domain, risk: "élevé", reason: "Typosquatting" }] : []),
    ...urls.slice(0, 5).map(u => ({ type: "url", value: u, risk: "moyen", reason: "Lien externe" })),
    ...ips.slice(0, 5).map(ip => ({ type: "ip", value: ip, risk: ip.startsWith("192.168.") || ip.startsWith("10.") ? "faible" : "moyen", reason: "IP source" })),
    ...keywords.slice(0, 5).map(k => ({ type: "keyword", value: k, risk: "faible", reason: "Mot-clé d'ingénierie sociale" })),
  ];
  const weights: Record<string, number> = { critique: 25, élevé: 15, moyen: 8, faible: 3 };
  const score = Math.min(100, iocs.reduce((a, i) => a + (weights[i.risk] || 3), 0));
  const level = score >= 70 ? "Critique" : score >= 40 ? "Élevé" : score >= 15 ? "Moyen" : "Faible";
  return {
    project: "P7", file: "email.eml", parsed: { from: sender, subject, to: headers["to"] || "", date: headers["date"] || "", received_ips: ips, urls, domains: [...new Set(urls.map(u => u.split("/")[2]))], suspicious_keywords: keywords },
    iocs, score: { score, level, ioc_count: iocs.length }, method: "Analyse locale d'email — 0 envoi distant",
  };
}