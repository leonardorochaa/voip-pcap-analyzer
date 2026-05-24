# Backend - VoIP PCAP Analyzer

API FastAPI para receber PCAP/PCAPNG, validar o upload e analisar sinalizacao SIP e midia RTP usando `tshark` local.

## Requisitos

- Python 3.11
- Wireshark/tshark instalado e disponivel no `PATH`

## Instalar e executar

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

No Windows PowerShell:

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

## Configuracao

Variaveis opcionais:

- `MAX_UPLOAD_MB`: limite de upload em MB. Padrao: `100`.
- `TSHARK_TIMEOUT_SECONDS`: timeout para cada chamada ao `tshark`. Padrao: `60`.
- `TSHARK_PATH`: caminho completo do executavel `tshark`, caso ele nao esteja no `PATH`.
- `AUDIO_MAX_STREAMS`: numero maximo de streams RTP extraidos para WAV na resposta. Padrao: `8`.
- `AUDIO_MAX_SECONDS`: duracao maxima extraida por stream. Padrao: `600`.
- `UPLOAD_DIR`: diretorio temporario de uploads. Padrao: `backend/tmp_uploads` quando executado a partir de `backend`.

No Windows, o backend tambem tenta localizar automaticamente:

- `C:\Program Files\Wireshark\tshark.exe`
- `C:\Program Files (x86)\Wireshark\tshark.exe`

## Endpoints

- `GET /api/health`: status do backend, disponibilidade e versao do `tshark`.
- `POST /api/analyze`: recebe multipart `file` com `.pcap` ou `.pcapng` e retorna a analise JSON.
- `POST /api/report/markdown`: recebe o JSON de analise e retorna relatorio Markdown.
- `POST /api/report/json`: recebe o JSON de analise e retorna JSON formatado.

O arquivo enviado e salvo em diretorio temporario e removido apos a analise.

## Extracao de audio RTP

Durante `POST /api/analyze`, o backend tenta extrair audio RTP para WAV embutido em base64 no JSON. Neste MVP, a decodificacao direta suporta G.711:

- PCMU / payload type 0
- PCMA / payload type 8

Streams com outros codecs aparecem no JSON com `extractable: false` e `unsupported_reason`.

A resposta tambem inclui `rtp_legs`, com as pernas esperadas pelo SDP e as pernas RTP recebidas no PCAP. Isso ajuda a identificar ausencia de midia em um dos sentidos e streams que possuem apenas CN/DTMF, sem audio de voz util.

Quando houver audio G.711 extraivel, a resposta inclui `audio_mix` com um WAV completo da chamada em base64, alem dos WAVs por stream em `audio_streams`.
