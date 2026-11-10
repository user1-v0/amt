"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import { API, Job, Payload, Verification } from "@/lib/types";
import CaseChat from "@/components/CaseChat";
import CodeViewer, { sourceForEvidence } from "@/components/CodeViewer";

const STAGES: Record<string, string> = {
  queued: "Queued.",
  unpacking: "Unpacking.",
  decompiling: "Decompiling DEX.",
  framework: "Unpacking framework code.",
  native: "Decompiling native libraries.",
  payloads: "First stage decoded.",
  decompiled: "Decompilation saved.",
  analyst: "Analysts are reading each manifest class.",
  correlate: "Main analyst is correlating the class findings.",
  "follow-up": "Analyst is questioning the interesting findings.",
  verifier: "Verifier is checking findings.",
  verdict: "Writing the label, type, and family.",
};

const SENSITIVE = [
  "SEND_SMS",
  "RECEIVE_SMS",
  "READ_SMS",
  "RECEIVE_MMS",
  "READ_CONTACTS",
  "WRITE_CONTACTS",
  "GET_ACCOUNTS",
  "ACCESS_FINE_LOCATION",
  "ACCESS_COARSE_LOCATION",
  "ACCESS_BACKGROUND_LOCATION",
  "CAMERA",
  "RECORD_AUDIO",
  "READ_CALL_LOG",
  "WRITE_CALL_LOG",
  "CALL_PHONE",
  "READ_PHONE_STATE",
  "REQUEST_INSTALL_PACKAGES",
  "INSTALL_PACKAGES",
  "DELETE_PACKAGES",
  "SYSTEM_ALERT_WINDOW",
  "BIND_ACCESSIBILITY_SERVICE",
  "BIND_DEVICE_ADMIN",
  "BIND_NOTIFICATION_LISTENER_SERVICE",
  "WRITE_SETTINGS",
  "WRITE_SECURE_SETTINGS",
  "READ_EXTERNAL_STORAGE",
  "WRITE_EXTERNAL_STORAGE",
  "MANAGE_EXTERNAL_STORAGE",
  "QUERY_ALL_PACKAGES",
  "PACKAGE_USAGE_STATS",
  "RECEIVE_BOOT_COMPLETED",
  "REQUEST_IGNORE_BATTERY_OPTIMIZATIONS",
];

function permissionName(permission: string) {
  return permission.split(".").pop() || permission;
}

const STATUS_ORDER = ["supported", "insufficient", "unsupported", "unverified"];

function Payloads({ files, note }: { files: Payload[]; note: string }) {
  if (!files.length && !note) return null;
  return (
    <section className="card">
      <h2>Payloads</h2>
      {note ? <p className="muted">{note}</p> : null}
      {files.map((payload) => (
        <article key={`${payload.name}-${payload.via}`} className="payload">
          <p>
            <strong className="mono">{payload.name}</strong>{" "}
            <span className="muted">
              {payload.kind} · {payload.via} · {payload.size.toLocaleString()} bytes
            </span>
          </p>
          {payload.detail ? <p className="detail">{payload.detail}</p> : null}
        </article>
      ))}
    </section>
  );
}

function nextActions(
  facts: {
    payloads?: unknown[];
    native_libs: { jni_methods?: string[] }[];
    components: { exported: boolean | null }[];
  },
  family: string,
) {
  const actions: string[] = [];
  if (facts.payloads?.length) actions.push("What did the static decode recover?");
  if (facts.native_libs.some((lib) => lib.jni_methods?.length)) actions.push("Which JNI method is actually called?");
  if (facts.components.some((component) => component.exported)) actions.push("What does the exported component do?");
  if (family === "dropper") actions.push("What does the app download or load?");
  if (!actions.length) actions.push("What behavior is shown in the decompiled code?");
  return actions.slice(0, 3);
}

function shownErrors(errors: string[]) {
  return errors.filter((item) => !/label the sample|verdict label was invalid/i.test(item));
}

function verdictSummary(summary: string) {
  const body = summary.replace(/^(?:label|verdict)\b[^.]*\.\s*/i, "").trim();
  return body || summary.trim();
}

function CodeSnippet({
  snippet,
  start,
  end,
  malicious,
}: {
  snippet: string;
  start: number;
  end: number;
  malicious: boolean;
}) {
  const safeStart = Math.max(0, Math.min(start, snippet.length));
  const safeEnd = Math.max(safeStart, Math.min(end, snippet.length));
  return (
    <pre className="snippet">
      <code>
        {snippet.slice(0, safeStart)}
        <mark className={malicious ? "malicious" : "cited"}>
          {snippet.slice(safeStart, safeEnd)}
        </mark>
        {snippet.slice(safeEnd)}
      </code>
    </pre>
  );
}

export default function JobPage({ params }: { params: Promise<{ id: string }> }) {
  const router = useRouter();
  const [id, setId] = useState("");
  const [job, setJob] = useState<Job | null>(null);
  const [error, setError] = useState("");
  const [starting, setStarting] = useState(false);
  const [focusPath, setFocusPath] = useState("");
  const [focusQuote, setFocusQuote] = useState("");

  async function reanalyze() {
    if (!id || starting) return;
    setStarting(true);
    setError("");
    const response = await fetch(`${API}/api/analyses/${id}/reanalyze`, { method: "POST" });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      setError(typeof payload.detail === "string" ? payload.detail : "Reanalyze failed.");
      setStarting(false);
      return;
    }
    const created = (await response.json()) as { id: string };
    router.push(`/jobs/${created.id}`);
  }

  useEffect(() => {
    params.then((value) => setId(value.id));
  }, [params]);

  useEffect(() => {
    if (!id) return;
    let timer = 0;
    async function load() {
      const response = await fetch(`${API}/api/analyses/${id}`);
      if (!response.ok) {
        setError("This analysis was not found.");
        return;
      }
      const body = (await response.json()) as Job;
      setJob(body);
      if (body.status === "queued" || body.status === "running") {
        timer = window.setTimeout(load, 2000);
      }
    }
    load().catch(() => setError("The analysis service is not running."));
    return () => window.clearTimeout(timer);
  }, [id]);

  const running = job?.status === "queued" || job?.status === "running";
  const report = job?.report;
  const facts = report?.facts;
  const payloads: Payload[] = facts?.payloads?.length ? facts.payloads : job?.payloads?.files || [];
  const payloadNote = payloads.length ? "" : job?.payloads?.note || "";
  const checks = new Map<string, Verification>(
    (report?.verification || []).map((item) => [item.id, item]),
  );

  return (
    <>
      <header className="top">
        <p className="crumb">
          <Link href="/">Samples</Link>
        </p>
        <div className="title-row">
          <h1>{job?.filename || "Analysis"}</h1>
          {job && !running ? (
            <button type="button" className="secondary" onClick={reanalyze} disabled={starting}>
              {starting ? "Starting…" : "Reanalyze"}
            </button>
          ) : null}
        </div>
        {facts?.package ? <p className="lede">{facts.package}</p> : null}
      </header>
      {error ? <p className="error">{error}</p> : null}
      {job?.error ? <p className="error">{job.error}</p> : null}
      {job && (job.status === "queued" || job.status === "running") ? (
        <p className="stage">{STAGES[job.stage || ""] || job.stage}</p>
      ) : null}
      {!facts ? <Payloads files={payloads} note={payloadNote} /> : null}
      {facts ? (
        <div className="stack">
          <section className="card">
            {report?.verdict ? (
              <>
                <p className="kicker">Type</p>
                <p className={`type ${report.verdict.malware_type || ""}`}>{report.verdict.malware_type}</p>
                <p className={`summary ${report.verdict.malware_type || ""}`}>{verdictSummary(report.verdict.summary)}</p>
                <dl className="fields">
                  <div>
                    <dt>Family</dt>
                    <dd>{report.verdict.family === "none" ? "—" : report.verdict.family}</dd>
                  </div>
                  <div>
                    <dt>Confidence</dt>
                    <dd>{report.verdict.confidence}</dd>
                  </div>
                </dl>
              </>
            ) : job?.status === "queued" || job?.status === "running" ? (
              <p className="muted">The review is still running.</p>
            ) : (
              <p className="muted">No verdict for this run.</p>
            )}
            {report?.errors?.length && shownErrors(report.errors).length ? (
              <p className="error">{shownErrors(report.errors).join(" ")}</p>
            ) : null}
          </section>
          <section className="card">
            <dl className="fields">
              <div>
                <dt>Version</dt>
                <dd>
                  {facts.version_name || "unknown"} ({facts.version_code || "unknown"})
                </dd>
              </div>
              <div>
                <dt>SHA-256</dt>
                <dd className="mono hash">{facts.original.sha256}</dd>
              </div>
              {facts.framework && facts.framework !== "android" ? (
                <div>
                  <dt>Framework</dt>
                  <dd>{facts.framework}</dd>
                </div>
              ) : null}
            </dl>
            {facts.permissions.some((permission) => SENSITIVE.includes(permissionName(permission))) ? (
              <>
                <span className="kicker">Sensitive permissions</span>
                <div className="chips">
                  {facts.permissions
                    .filter((permission) => SENSITIVE.includes(permissionName(permission)))
                    .map((permission) => (
                      <span key={permission} className="chip mono">
                        {permissionName(permission)}
                      </span>
                    ))}
                </div>
              </>
            ) : null}
            {facts.components.length ? (
              <>
                <span className="kicker">Manifest classes</span>
                <ul className="compact">
                  {facts.components.map((component) => (
                    <li key={`${component.kind}-${component.name}`}>
                      <span className="muted">{component.kind}</span>{" "}
                      <span className="mono">{component.name}</span>{" "}
                      <span className="muted">
                        {component.exported === true ? "exported" : component.exported === false ? "not exported" : ""}
                      </span>
                    </li>
                  ))}
                </ul>
              </>
            ) : null}
            {facts.native_libs.some((lib) => lib.jni_methods?.length) ? (
              <>
                <span className="kicker">JNI methods</span>
                <ul className="compact">
                  {facts.native_libs.flatMap((lib) =>
                    (lib.jni_methods || []).map((method) => (
                      <li key={`${lib.name}-${method}`}>
                        <span className="mono">{lib.name}</span>{" "}
                        <span className="muted">{method.replace(/^sym\./, "")}</span>
                      </li>
                    )),
                  )}
                </ul>
              </>
            ) : null}
          </section>
          <Payloads files={payloads} note={payloadNote} />
          <CodeViewer
            jobId={id}
            focusPath={focusPath}
            focusQuote={focusQuote}
            components={facts.components.map((component) => ({
              name: component.name,
              exported: component.exported,
            }))}
          />
          <section className="card">
            <h2>Findings</h2>
            {report?.hypotheses.length ? (
              [...report.hypotheses]
                .sort(
                  (left, right) =>
                    STATUS_ORDER.indexOf(checks.get(left.id)?.status || "unverified") -
                    STATUS_ORDER.indexOf(checks.get(right.id)?.status || "unverified"),
                )
                .map((finding) => {
                  const check = checks.get(finding.id);
                  return (
                    <article key={finding.id} className="finding">
                      <p>
                        <strong>{finding.id}</strong>{" "}
                        <span className={`pill ${check?.status || ""}`}>{check?.status || "unverified"}</span>{" "}
                        <span className="muted">{finding.confidence}</span>
                      </p>
                      <p>{finding.behavior}</p>
                      {check && check.status !== "supported" ? <p className="muted">{check.note}</p> : null}
                      {finding.evidence.map((item) => {
                        const malicious = check?.status === "supported";
                        const snippet = item.snippet || item.quote;
                        return (
                          <figure key={`${item.path}-${item.quote}`}>
                            <figcaption className="mono">
                              {item.path} {item.symbol}{" "}
                              <button
                                type="button"
                                className="text-button"
                                onClick={() => {
                                  setFocusPath(sourceForEvidence(item.path));
                                  setFocusQuote(item.quote);
                                  document.getElementById("viewer")?.scrollIntoView({ behavior: "smooth", block: "start" });
                                }}
                              >
                                Open
                              </button>
                            </figcaption>
                            <CodeSnippet
                              snippet={snippet}
                              start={item.highlight_start ?? 0}
                              end={item.highlight_end ?? snippet.length}
                              malicious={malicious}
                            />
                          </figure>
                        );
                      })}
                    </article>
                  );
                })
            ) : (
              <p className="muted">No findings were recorded.</p>
            )}
          </section>
          <CaseChat jobId={id} suggestions={nextActions(facts, report?.verdict?.family || "")} />
        </div>
      ) : null}
    </>
  );
}
