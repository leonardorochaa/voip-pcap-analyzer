import os
from pathlib import Path


class Settings:
    app_name: str = "VoIP PCAP Analyzer"
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]
    max_upload_mb: int = int(os.getenv("MAX_UPLOAD_MB", "100"))
    tshark_timeout_seconds: int = int(os.getenv("TSHARK_TIMEOUT_SECONDS", "60"))
    tshark_path: str | None = os.getenv("TSHARK_PATH")
    audio_max_streams: int = int(os.getenv("AUDIO_MAX_STREAMS", "8"))
    audio_max_seconds: int = int(os.getenv("AUDIO_MAX_SECONDS", "600"))
    upload_dir: Path = Path(os.getenv("UPLOAD_DIR", Path.cwd() / "tmp_uploads"))

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024


settings = Settings()
