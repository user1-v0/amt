"use client";

import { FormEvent, useState } from "react";
import { API } from "@/lib/types";

type Turn = { role: "you" | "case"; text: string };

export default function CaseChat({ jobId, suggestions }: { jobId: string; suggestions: string[] }) {
  const [draft, setDraft] = useState("");
  const [turns, setTurns] = useState<Turn[]>([]);
  const [actions, setActions] = useState(suggestions);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  async function ask(message: string) {
    const text = message.trim();
    if (!text || busy) return;
    setBusy(true);
    setError("");
    setDraft("");
    setTurns((current) => [...current, { role: "you", text }]);
    try {
      const response = await fetch(`${API}/api/analyses/${jobId}/chat`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ message: text }),
      });
      const body = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(body.detail || "The case assistant is unavailable.");
      setTurns((current) => [...current, { role: "case", text: body.reply || "No answer." }]);
      if (Array.isArray(body.actions) && body.actions.length) setActions(body.actions.slice(0, 3));
    } catch (exc) {
      setError(exc instanceof Error ? exc.message : "The case assistant is unavailable.");
    } finally {
      setBusy(false);
    }
  }

  function onSubmit(event: FormEvent) {
    event.preventDefault();
    void ask(draft);
  }

  return (
    <section className="card chat">
      <h2>Ask about this sample</h2>
      <div className="suggestions">
        {actions.map((action) => (
          <button key={action} type="button" className="suggestion" onClick={() => void ask(action)} disabled={busy}>
            {action}
          </button>
        ))}
      </div>
      {turns.map((turn, index) => (
        <p key={`${turn.role}-${index}`} className={turn.role === "you" ? "turn you" : "turn"}>
          {turn.text}
        </p>
      ))}
      {error ? <p className="error">{error}</p> : null}
      <form className="ask" onSubmit={onSubmit}>
        <input
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          placeholder="Ask about a class, a native method, or the decoded data"
          aria-label="Ask about this sample"
        />
        <button type="submit" disabled={busy || !draft.trim()}>
          {busy ? "Asking…" : "Ask"}
        </button>
      </form>
    </section>
  );
}
