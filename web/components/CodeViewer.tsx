"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { API } from "@/lib/types";

export type SourceFile = { path: string; kind: string; size: number };
export type ManifestClass = { name: string; exported: boolean | null };

const GROUPS = ["manifest", "native", "stage1", "crypto", "framework", "dex", "other"] as const;

const LABELS: Record<string, string> = {
  dex: "DEX",
  native: "Native",
  stage1: "Stage 1",
  crypto: "Crypto",
  framework: "Framework",
  manifest: "Manifest",
  other: "Other",
};

function fileLabel(path: string) {
  if (path.endsWith("manifest.xml")) return "AndroidManifest.xml";
  return path.split("/").pop() || path;
}

function classStem(path: string) {
  return fileLabel(path).replace(/\.(java|smali|kt)$/i, "");
}

function filesForViewer(files: SourceFile[]) {
  const manifestStems = new Set(
    files.filter((file) => file.path.startsWith("dex/")).map((file) => classStem(file.path)),
  );
  return files.flatMap((file) => {
    if (!file.path.startsWith("ondemand/")) return [file];
    const stem = classStem(file.path);
    if (manifestStems.has(stem)) return [];
    const inner = [...manifestStems].some(
      (name) => stem.startsWith(`${name}_`) || stem.startsWith(`${name}$`),
    );
    return inner ? [{ ...file, kind: "manifest" }] : [file];
  });
}

function manifestSections(files: SourceFile[], components: ManifestClass[]) {
  const xml = files.filter((file) => file.path.endsWith("manifest.xml"));
  const exported: SourceFile[] = [];
  const hidden: SourceFile[] = [];
  const other: SourceFile[] = [];
  for (const file of files) {
    if (file.path.endsWith("manifest.xml")) continue;
    const stem = classStem(file.path);
    const match = components.find(
      (component) =>
        component.name === stem ||
        stem.startsWith(`${component.name}_`) ||
        stem.startsWith(`${component.name}$`),
    );
    const bucket = match?.exported === true ? exported : match?.exported === false ? hidden : other;
    bucket.push(file);
  }
  const byName = (left: SourceFile, right: SourceFile) => left.path.localeCompare(right.path);
  return [
    { label: "", files: xml },
    { label: "", files: other.sort(byName) },
    { label: "Exported", files: exported.sort(byName) },
    { label: "Not exported", files: hidden.sort(byName) },
  ].filter((section) => section.files.length);
}

function lineHits(text: string, quote: string) {
  const needle = quote.trim();
  const hits = new Set<number>();
  if (needle.length < 8) return hits;
  const at = text.indexOf(needle);
  if (at < 0) return hits;
  const start = text.slice(0, at).split("\n").length;
  const end = text.slice(0, at + needle.length).split("\n").length;
  for (let line = start; line <= end; line += 1) hits.add(line);
  return hits;
}

export function sourceForEvidence(path: string) {
  if (path.endsWith(".so")) return `native/notes/${path.split("/").pop()}.txt`;
  return path;
}

export default function CodeViewer({
  jobId,
  focusPath,
  focusQuote,
  components = [],
}: {
  jobId: string;
  focusPath: string;
  focusQuote: string;
  components?: ManifestClass[];
}) {
  const [files, setFiles] = useState<SourceFile[]>([]);
  const [selected, setSelected] = useState("");
  const [text, setText] = useState("");
  const [truncated, setTruncated] = useState(false);
  const [error, setError] = useState("");
  const hitRef = useRef<HTMLSpanElement | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetch(`${API}/api/analyses/${jobId}/files`)
      .then(async (response) => {
        if (!response.ok) throw new Error("files");
        return response.json() as Promise<{ files: SourceFile[] }>;
      })
      .then((body) => {
        if (cancelled) return;
        setFiles(body.files || []);
        setSelected((current) => current || body.files?.[0]?.path || "");
      })
      .catch(() => {
        if (!cancelled) setError("Decompiled files are not available yet.");
      });
    return () => {
      cancelled = true;
    };
  }, [jobId]);

  useEffect(() => {
    if (!focusPath) return;
    const known = files.some((file) => file.path === focusPath);
    if (known || focusPath.endsWith(".txt") || focusPath.endsWith(".java") || focusPath.endsWith(".smali")) {
      setSelected(focusPath);
    }
  }, [focusPath, files]);

  useEffect(() => {
    if (!selected) return;
    let cancelled = false;
    setError("");
    fetch(`${API}/api/analyses/${jobId}/file?path=${encodeURIComponent(selected)}`)
      .then(async (response) => {
        if (!response.ok) throw new Error("file");
        return response.json() as Promise<{ text: string; truncated: boolean }>;
      })
      .then((body) => {
        if (cancelled) return;
        setText(body.text || "");
        setTruncated(Boolean(body.truncated));
      })
      .catch(() => {
        if (!cancelled) {
          setText("");
          setError("This file could not be opened.");
        }
      });
    return () => {
      cancelled = true;
    };
  }, [jobId, selected]);

  const hits = useMemo(() => lineHits(text, focusPath === selected ? focusQuote : ""), [text, focusPath, selected, focusQuote]);
  const lines = text.split("\n");

  useEffect(() => {
    hitRef.current?.scrollIntoView({ block: "center" });
  }, [text, selected, focusQuote]);

  const visible = useMemo(() => filesForViewer(files), [files]);
  const grouped = GROUPS.map((kind) => ({
    kind,
    files: visible
      .filter((file) => file.kind === kind)
      .sort((left, right) => {
        const leftXml = left.path.endsWith("manifest.xml") ? 0 : 1;
        const rightXml = right.path.endsWith("manifest.xml") ? 0 : 1;
        return leftXml - rightXml || left.path.localeCompare(right.path);
      }),
  })).filter((group) => group.files.length);

  return (
    <section className="card viewer" id="viewer">
      <div className="files">
        <h2>Code</h2>
        {grouped.length ? (
          grouped.map((group) => (
            <div key={group.kind}>
              <p className="kicker">{LABELS[group.kind] || group.kind}</p>
              {(group.kind === "manifest" ? manifestSections(group.files, components) : [{ label: "", files: group.files }]).map(
                (section, index) => (
                  <div key={`${section.label}-${index}`}>
                    {section.label ? <p className="kicker">{section.label}</p> : null}
                    {section.files.map((file) => (
                      <button
                        key={file.path}
                        type="button"
                        className={file.path === selected ? "file current" : "file"}
                        onClick={() => setSelected(file.path)}
                      >
                        {fileLabel(file.path)}
                      </button>
                    ))}
                  </div>
                ),
              )}
            </div>
          ))
        ) : (
          <p className="muted">{error || "No decompiled files yet."}</p>
        )}
      </div>
      <div className="editor">
        <p className="editor-path mono">{selected || "Select a file"}</p>
        {error && selected ? <p className="error">{error}</p> : null}
        {truncated ? <p className="muted">Showing the first 200,000 characters.</p> : null}
        <pre className="code">
          <code>
            {lines.map((line, index) => {
              const number = index + 1;
              const hit = hits.has(number);
              return (
                <span
                  key={number}
                  ref={hit && number === Math.min(...hits) ? hitRef : undefined}
                  className={hit ? "code-line hit" : "code-line"}
                >
                  <span className="ln">{number}</span>
                  {line || " "}
                </span>
              );
            })}
          </code>
        </pre>
      </div>
    </section>
  );
}
