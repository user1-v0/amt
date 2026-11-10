"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { API, JobSummary } from "@/lib/types";

export default function HomePage() {
  const [file, setFile] = useState<File | null>(null);
  const [factsOnly, setFactsOnly] = useState(false);
  const [busy, setBusy] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState("");
  const [jobs, setJobs] = useState<JobSummary[]>([]);

  async function refresh() {
    const response = await fetch(`${API}/api/analyses`);
    if (response.ok) setJobs(await response.json());
  }

  useEffect(() => {
    refresh().catch(() => setError("The analysis service is not running."));
  }, []);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    if (!file) return;
    setBusy(true);
    setError("");
    const body = new FormData();
    body.set("file", file);
    body.set("facts_only", String(factsOnly));
    const response = await fetch(`${API}/api/analyses`, { method: "POST", body });
    setBusy(false);
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      setError(payload.detail || "Upload failed.");
      return;
    }
    const job = await response.json();
    window.location.href = `/jobs/${job.id}`;
  }

  const trojans = jobs.filter((job) => job.malware_type === "trojan").length;
  const pups = jobs.filter((job) => job.malware_type === "pup").length;
  const active = jobs.filter((job) => job.status === "queued" || job.status === "running").length;

  function takeFile(next: File | null) {
    if (!next) return;
    const suffix = next.name.split(".").pop()?.toLowerCase();
    if (suffix !== "apk" && suffix !== "xapk" && suffix !== "apks") {
      setError("Upload an APK, XAPK, or APKS file.");
      return;
    }
    setError("");
    setFile(next);
  }

  return (
    <>
      <header className="top">
        <p className="brand">mr-amt</p>
        <h1>Samples</h1>
        <p className="lede">Static review. The sample is not installed or run.</p>
      </header>
      <form className="upload card" onSubmit={onSubmit}>
        <label
          className={dragOver ? "drop over" : "drop"}
          onDragOver={(event) => {
            event.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(event) => {
            event.preventDefault();
            setDragOver(false);
            takeFile(event.dataTransfer.files?.[0] ?? null);
          }}
        >
          <input
            type="file"
            accept=".apk,.xapk,.apks"
            onChange={(event) => takeFile(event.target.files?.[0] ?? null)}
          />
          <span className="kicker">Sample</span>
          <strong>{file ? file.name : "Drop an APK, XAPK, or APKS"}</strong>
          <span className="muted">
            {file ? `${(file.size / (1024 * 1024)).toFixed(1)} MB` : "or click to choose a file"}
          </span>
        </label>
        <div className="upload-actions">
          <label className="check">
            <input
              type="checkbox"
              checked={factsOnly}
              onChange={(event) => setFactsOnly(event.target.checked)}
            />
            Facts only
          </label>
          <button type="submit" disabled={!file || busy}>
            {busy ? "Uploading…" : "Analyze"}
          </button>
        </div>
        {error ? <p className="error">{error}</p> : null}
      </form>
      <p className="tally">
        <strong>{jobs.length}</strong> samples
        <span>·</span>
        <strong className="trojan">{trojans}</strong> trojan
        <span>·</span>
        <strong className="pup">{pups}</strong> pup
        <span>·</span>
        <strong>{active}</strong> running
      </p>
      <section className="card">
        <h2>Recent</h2>
        {jobs.length ? (
          <div className="sample-table">
            {jobs.map((job) => {
              const status = job.facts_only && job.status === "done" ? "facts" : job.status;
              const family = job.family && job.family !== "none" ? job.family : "";
              const detail = [job.package, family, status].filter(Boolean);
              return (
                <Link key={job.id} href={`/jobs/${job.id}`} className="sample-row">
                  <strong>{job.filename}</strong>
                  <span className="muted">
                    {job.malware_type ? <span className={job.malware_type}>{job.malware_type}</span> : null}
                    {job.malware_type && detail.length ? " · " : null}
                    {detail.join(" · ")}
                  </span>
                </Link>
              );
            })}
          </div>
        ) : (
          <p className="muted">No samples yet.</p>
        )}
      </section>
    </>
  );
}
