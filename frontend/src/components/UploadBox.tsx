import { ChangeEvent, DragEvent, useRef, useState } from "react";
import { FileUp, Loader2, UploadCloud } from "lucide-react";

interface UploadBoxProps {
  loading: boolean;
  onUpload: (file: File) => void;
}

export function UploadBox({ loading, onUpload }: UploadBoxProps) {
  const inputRef = useRef<HTMLInputElement | null>(null);
  const [dragging, setDragging] = useState(false);

  function handleFiles(files: FileList | null) {
    const file = files?.[0];
    if (file) {
      onUpload(file);
    }
  }

  function onDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragging(false);
    handleFiles(event.dataTransfer.files);
  }

  function onInput(event: ChangeEvent<HTMLInputElement>) {
    handleFiles(event.target.files);
    event.target.value = "";
  }

  return (
    <div
      className={`uploadBox ${dragging ? "dragging" : ""}`}
      onDragOver={(event) => {
        event.preventDefault();
        setDragging(true);
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={onDrop}
      role="button"
      tabIndex={0}
      onClick={() => inputRef.current?.click()}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          inputRef.current?.click();
        }
      }}
    >
      <input ref={inputRef} type="file" accept=".pcap,.pcapng" onChange={onInput} />
      <div className="uploadIcon">{loading ? <Loader2 className="spin" /> : <UploadCloud />}</div>
      <div>
        <h2>{loading ? "Analisando captura" : "Solte um PCAP ou PCAPNG"}</h2>
        <p>Upload local para analise SIP/RTP com tshark.</p>
      </div>
      <button className="primaryButton" type="button" disabled={loading}>
        <FileUp size={18} />
        Selecionar arquivo
      </button>
    </div>
  );
}
