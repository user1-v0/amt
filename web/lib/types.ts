export type JobSummary = {
  id: string;
  filename: string;
  facts_only: boolean;
  status: string;
  stage?: string;
  error: string | null;
  created_at: string;
  package: string | null;
  verdict: string | null;
  malware_type?: string | null;
  family?: string | null;
};

export type Evidence = {
  path: string;
  symbol: string;
  quote: string;
  snippet?: string;
  highlight_start?: number;
  highlight_end?: number;
};
export type Finding = {
  id: string;
  behavior: string;
  confidence: string;
  evidence: Evidence[];
};
export type Verification = { id: string; status: string; note: string };
export type Verdict = {
  verdict: string;
  family: string;
  confidence: string;
  summary: string;
  supporting_finding_ids: string[];
  malicious?: boolean;
  malware_type?: string;
};
export type Fingerprint = { kind: string; name: string; sha256: string };
export type ComponentInfo = {
  kind: string;
  name: string;
  exported: boolean | null;
  actions: string[];
  status: string;
  error?: string | null;
};
export type NativeLib = {
  name: string;
  abi: string;
  status: string;
  pseudocode: boolean;
  note: string | null;
  functions: string[];
  jni_methods?: string[];
};
export type Payload = {
  name: string;
  kind: string;
  via: string;
  size: number;
  detail: string;
};
export type PayloadUpdate = { files?: Payload[]; note?: string };
export type Report = {
  facts: {
    original: { name: string; size: number; md5: string; sha1: string; sha256: string };
    container: string;
    package: string | null;
    framework?: string;
    framework_files?: string[];
    version_name: string | null;
    version_code: string | null;
    app_label: string | null;
    app_label_ref: string | null;
    permissions: string[];
    components: ComponentInfo[];
    native_libs: NativeLib[];
    stage_notes: string[];
    fingerprints?: Fingerprint[];
    payloads?: Payload[];
  };
  hypotheses: Finding[];
  verification: Verification[];
  verdict: Verdict | null;
  errors: string[];
};
export type Job = JobSummary & { report: Report | null; payloads?: PayloadUpdate | null };

export const API = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000";
