# Frontend - VoIP PCAP Analyzer

Interface React/Vite para upload de PCAP/PCAPNG e visualizacao da analise SIP/RTP retornada pelo backend.

## Instalar e executar

```bash
cd frontend
npm install
npm run dev
```

A aplicacao abre em `http://localhost:5173`.

## Configuracao

Por padrao o frontend consome `http://localhost:8000`.

Para alterar:

```bash
VITE_API_BASE_URL=http://localhost:8000 npm run dev
```

No Windows PowerShell:

```powershell
$env:VITE_API_BASE_URL="http://localhost:8000"
npm run dev
```

## Funcionalidades

- Upload drag-and-drop.
- Estados de loading, erro e sucesso.
- Cards de status, codigo SIP, duracao, codec, RTP, perda, jitter e causa provavel.
- Timeline SIP com erros destacados.
- Diagrama visual SIP/RTP em estilo ladder, com setas entre IPs.
- Tabela para multiplos Call-IDs.
- RTP Player com pernas recebidas/ausentes/sem voz, waveform por stream, player de audio na web, audio completo mixado e download WAV.
- Paineis de diagnostico, resolucao sugerida e JSON tecnico expansivel.
- Exportacao local de relatorio Markdown e JSON.
