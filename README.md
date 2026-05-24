# VoIP PCAP Analyzer

Ferramenta para análise de chamadas VoIP a partir de arquivos PCAP/PCAPNG, com foco em diagnóstico de problemas de sinalização SIP e mídia RTP.

Ideal para:

* Troubleshooting de chamadas (sem áudio, falhas, quedas)
* Análise de capturas de rede em ambientes VoIP
* Engenheiros de redes e telecom

O sistema processa automaticamente capturas utilizando `tshark` e apresenta os dados de forma estruturada e visual.

---

## 🚀 Funcionalidades

* Análise de sinalização SIP (códigos, fluxo, erros)
* Identificação de falhas comuns em chamadas
* Estatísticas RTP (perda de pacotes, jitter, streams)
* Detecção de ausência de mídia em um ou ambos os sentidos
* Extração de áudio G.711 (PCMU / PCMA)
* Geração de relatório em Markdown e JSON
* Interface web interativa para visualização

---

## 🖥️ Interface

📸 **Adicione aqui screenshots reais do seu sistema:**

<img width="1315" height="310" alt="image" src="https://github.com/user-attachments/assets/defe11ef-33e7-45a4-8efc-f48ad01792e6" />
<img width="1294" height="630" alt="image" src="https://github.com/user-attachments/assets/0b494bda-88ae-4626-8f86-89b459ed45ab" />
<img width="1260" height="850" alt="image" src="https://github.com/user-attachments/assets/f39be7ef-73ad-4c71-bee9-6d94fb9c2978" />
<img width="1269" height="788" alt="image" src="https://github.com/user-attachments/assets/5540c3f4-dd38-455c-8e1b-eed465845c65" />
<img width="1272" height="214" alt="image" src="https://github.com/user-attachments/assets/e77cc2b3-7082-425e-96be-e589b80c4843" />


---

## 🧠 Motivação

Ferramentas como Wireshark são extremamente poderosas, mas exigem análise manual e conhecimento aprofundado.

Este projeto automatiza a identificação de problemas comuns em chamadas VoIP, reduzindo o tempo de diagnóstico e facilitando a visualização dos dados.

---

## 🏗️ Arquitetura

* **Backend:** FastAPI responsável por processar os arquivos PCAP utilizando `tshark`
* **Frontend:** React + Vite para upload e visualização dos dados

```id="sksn21"
backend/   → API e processamento PCAP
frontend/  → Interface web
```

---

## ⚙️ Como rodar o projeto

### 1. Backend

```bash id="q8p2nz"
cd backend
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

**Windows PowerShell:**

```powershell id="z81kxa"
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

---

### 2. Frontend

```bash id="n2s8lp"
cd frontend
npm install
npm run dev
```

A aplicação estará disponível em:

* Frontend: http://localhost:5173
* Backend: http://localhost:8000

---

## 🔧 Configuração

### Backend

Variáveis opcionais:

* `MAX_UPLOAD_MB` (default: 100)
* `TSHARK_TIMEOUT_SECONDS` (default: 60)
* `TSHARK_PATH` (caso não esteja no PATH)
* `AUDIO_MAX_STREAMS` (default: 8)
* `AUDIO_MAX_SECONDS` (default: 600)
* `UPLOAD_DIR` (diretório temporário)

No Windows, o sistema tenta localizar automaticamente:

```id="9w2pka"
C:\Program Files\Wireshark\tshark.exe
C:\Program Files (x86)\Wireshark\tshark.exe
```

---

### Frontend

Por padrão:

```id="zq7m31"
http://localhost:8000
```

Para alterar:

```bash id="l2m4qp"
VITE_API_BASE_URL=http://localhost:8000 npm run dev
```

**Windows PowerShell:**

```powershell id="0m1zvc"
$env:VITE_API_BASE_URL="http://localhost:8000"
npm run dev
```

---

## 📡 Endpoints principais

* `GET /api/health` → status do backend
* `POST /api/analyze` → upload e análise do PCAP
* `POST /api/report/markdown` → geração de relatório Markdown
* `POST /api/report/json` → geração de JSON formatado

---

## 🔊 Extração de áudio RTP

Durante a análise, o sistema tenta extrair áudio RTP:

Suporte atual:

* G.711 PCMU (payload 0)
* G.711 PCMA (payload 8)

Inclui:

* Áudio por stream
* Áudio mixado da chamada
* Identificação de streams sem voz útil (CN/DTMF)

---

## ⚠️ Observações

* Requer Wireshark/tshark instalado
* Projeto em fase MVP
* Focado inicialmente em análise de VoIP com SIP + RTP
