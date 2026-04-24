import { useCallback, useEffect, useRef, useState } from "react";
import { LuDownload, LuTrash2, LuUpload } from "react-icons/lu";

import { GridCard } from "@components/Card";
import { SettingsPageHeader } from "@components/SettingsPageheader";
import { Button } from "@components/Button";
import { formatters } from "@/utils";

interface TransferFile {
  id: string;
  name: string;
  size: number;
  uploadedAt: string;
  from: "target" | "operator";
}

interface FileListResponse {
  files: TransferFile[];
  usedBytes: number;
  capBytes: number;
}

function fmtAge(iso: string): string {
  const secs = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (secs < 5) return "just now";
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  return `${Math.round(secs / 3600)}h ago`;
}

export default function FileTransferPopover() {
  const [files, setFiles] = useState<TransferFile[]>([]);
  const [usedBytes, setUsedBytes] = useState(0);
  const [capBytes, setCapBytes] = useState(1 << 30);
  const [uploading, setUploading] = useState(false);
  const [uploadStatus, setUploadStatus] = useState<string | null>(null);
  const [isDragOver, setIsDragOver] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const loadFiles = useCallback(async () => {
    try {
      const resp = await fetch("/api/transfer/op");
      if (!resp.ok) return;
      const data = (await resp.json()) as FileListResponse;
      setFiles(data.files ?? []);
      setUsedBytes(data.usedBytes ?? 0);
      setCapBytes(data.capBytes ?? 1 << 30);
    } catch {
      // ignore network errors
    }
  }, []);

  useEffect(() => {
    void loadFiles();
    pollRef.current = setInterval(() => void loadFiles(), 5000);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [loadFiles]);

  const uploadFiles = useCallback(
    async (fileList: File[]) => {
      if (!fileList.length) return;
      setUploading(true);
      let succeeded = 0;
      for (const file of fileList) {
        setUploadStatus(`Uploading ${file.name}…`);
        const fd = new FormData();
        fd.append("file", file);
        try {
          const resp = await fetch("/api/transfer/op", { method: "POST", body: fd });
          if (resp.ok) {
            succeeded++;
          } else {
            const err = (await resp.json().catch(() => ({ error: "upload failed" }))) as {
              error: string;
            };
            setUploadStatus(`✗ ${file.name}: ${err.error}`);
          }
        } catch {
          setUploadStatus(`✗ ${file.name}: network error`);
        }
      }
      if (succeeded > 0) {
        setUploadStatus(`✓ ${succeeded} file(s) sent to target`);
        void loadFiles();
      }
      setUploading(false);
      setTimeout(() => setUploadStatus(null), 3000);
    },
    [loadFiles],
  );

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragOver(false);
      void uploadFiles(Array.from(e.dataTransfer.files));
    },
    [uploadFiles],
  );

  const handleDelete = useCallback(
    async (id: string) => {
      try {
        await fetch(`/api/transfer/${id}`, { method: "DELETE" });
        void loadFiles();
      } catch {
        // ignore
      }
    },
    [loadFiles],
  );

  const fromTarget = files.filter(f => f.from === "target");
  const fromOperator = files.filter(f => f.from === "operator");
  const usedPct = Math.min(100, Math.round((usedBytes / capBytes) * 100));

  return (
    <GridCard>
      <div className="space-y-3 p-4 py-3">
        <SettingsPageHeader
          title="File Transfer"
          description="Send files to the target machine or download files it sent you."
        />

        {/* Storage bar */}
        <div>
          <div className="mb-1 flex justify-between text-xs text-slate-500 dark:text-slate-400">
            <span>Storage used</span>
            <span>
              {formatters.bytes(usedBytes)} / {formatters.bytes(capBytes)}
            </span>
          </div>
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-700">
            <div
              className="h-full rounded-full transition-all duration-300"
              style={{
                width: `${usedPct}%`,
                background: usedPct > 80 ? "#ef4444" : "#3b82f6",
              }}
            />
          </div>
        </div>

        {/* Upload drop zone → operator sends to target */}
        <div>
          <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-slate-400 dark:text-slate-500">
            Send to target
          </p>
          <div
            className={`cursor-pointer rounded-lg border-2 border-dashed px-4 py-5 text-center transition-all ${
              isDragOver
                ? "border-blue-500 bg-blue-50 dark:bg-blue-950"
                : "border-slate-300 dark:border-slate-600"
            }`}
            onClick={() => fileInputRef.current?.click()}
            onDragOver={e => {
              e.preventDefault();
              setIsDragOver(true);
            }}
            onDragLeave={() => setIsDragOver(false)}
            onDrop={handleDrop}
          >
            <input
              ref={fileInputRef}
              type="file"
              multiple
              className="hidden"
              onChange={e => {
                if (e.target.files?.length) void uploadFiles(Array.from(e.target.files));
                e.target.value = "";
              }}
            />
            <LuUpload className="mx-auto mb-1.5 h-5 w-5 text-slate-400" />
            <p className="text-sm text-slate-600 dark:text-slate-300">
              Drop files here or <span className="font-semibold">click to browse</span>
            </p>
            <p className="mt-0.5 text-xs text-slate-400">Max 1 GB total — oldest removed when full</p>
          </div>
          {(uploading || uploadStatus) && (
            <p className="mt-1.5 text-xs text-slate-500 dark:text-slate-400">
              {uploadStatus ?? "Uploading…"}
            </p>
          )}
        </div>

        {/* Files sent to target (from operator) */}
        {fromOperator.length > 0 && (
          <div>
            <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-slate-400 dark:text-slate-500">
              Sent to target
            </p>
            <div className="flex flex-col gap-1.5">
              {fromOperator.map(f => (
                <FileRow key={f.id} file={f} onDelete={handleDelete} showDelete />
              ))}
            </div>
          </div>
        )}

        {/* Files from target */}
        <div>
          <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-slate-400 dark:text-slate-500">
            From target
          </p>
          {fromTarget.length === 0 ? (
            <p className="text-xs text-slate-400 dark:text-slate-500">No files from target yet.</p>
          ) : (
            <div className="flex flex-col gap-1.5">
              {fromTarget.map(f => (
                <FileRow key={f.id} file={f} onDelete={handleDelete} showDelete downloadUrl={`/api/transfer/op/${f.id}`} />
              ))}
            </div>
          )}
        </div>

        <div className="flex justify-end pt-1">
          <Button size="SM" theme="light" text="Refresh" onClick={() => void loadFiles()} />
        </div>
      </div>
    </GridCard>
  );
}

function FileRow({
  file,
  onDelete,
  showDelete,
  downloadUrl,
}: {
  file: TransferFile;
  onDelete: (id: string) => void;
  showDelete?: boolean;
  downloadUrl?: string;
}) {
  const dlHref = downloadUrl ?? `/api/transfer/op/${file.id}`;
  return (
    <div className="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 dark:border-slate-700 dark:bg-slate-800">
      <div className="min-w-0 flex-1">
        <p
          className="truncate text-sm font-medium text-slate-900 dark:text-slate-100"
          title={file.name}
        >
          {file.name}
        </p>
        <p className="text-xs text-slate-400">
          {formatters.bytes(file.size)} · {fmtAge(file.uploadedAt)}
        </p>
      </div>
      <a
        href={dlHref}
        download={file.name}
        className="flex-shrink-0 rounded p-1 text-blue-600 hover:bg-blue-50 dark:text-blue-400 dark:hover:bg-blue-900"
        title="Download"
      >
        <LuDownload className="h-4 w-4" />
      </a>
      {showDelete && (
        <button
          className="flex-shrink-0 rounded p-1 text-slate-400 hover:bg-slate-200 hover:text-red-500 dark:hover:bg-slate-700"
          title="Delete"
          onClick={() => onDelete(file.id)}
        >
          <LuTrash2 className="h-4 w-4" />
        </button>
      )}
    </div>
  );
}
