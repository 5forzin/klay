# Usando o klay com outra IA

O klay (Kernel Relay) entrega no host evidências de crashes de kernel de uma VM Windows. A coleta ocorre após o Windows reiniciar. Use o código do Bug Check, os parâmetros, o dump e a análise do KD para investigar o driver e consultar o código-fonte correspondente.

## Antes de começar

Leia o README e a configuração usada pelo monitor. O arquivo padrão é `%LOCALAPPDATA%\Klay\config.json`. Para outra VM, coloque `--config 'C:\Caminho\config.json'` antes de cada comando e passe `-Config` aos scripts do host. Use o mesmo arquivo em todas as operações.

Os exemplos usam `klay` no PATH. Em uma instalação com o ambiente virtual do README, substitua por `.\.venv\Scripts\klay.exe` ou ative o ambiente virtual. Execute os scripts a partir do checkout do projeto.

```powershell
$config = Get-Content "$env:LOCALAPPDATA\Klay\config.json" -Raw | ConvertFrom-Json
klay status
```

`status` lê arquivos do monitor; não faz uma consulta nova ao guest. Consulte novamente após alguns segundos e confirme que `status.hostTimeUtc` avançou. Verifique:

- `status.guestHeartbeatAgeSeconds`: idade do heartbeat do guest.
- `status.guestReachability`: `online` com heartbeat recente; `unknown` quando não há informação recente.
- `status.rebootRequired`: reinício pendente após a instalação.
- `status.currentBootDumpErrors`: eventos `volmgr` 46/161 desde o boot atual.
- `status.guestHeartbeat.pagefiles`: pagefiles ativos após o reinício.
- `latest.crashId` e `latest.analysisState`: último crash observado e andamento da análise.

Heartbeat antigo pode indicar VM desligada, share indisponível ou cópia de um dump grande. Sozinho, ele não comprova BSOD. Um `latest` antigo também não comprova que o teste atual falhou.

## Vincular a build antes do teste

Use o `.sys` e o `.pdb` produzidos pela mesma compilação:

```powershell
klay arm --driver 'C:\DriverProject\x64\Debug\Example.sys' `
    --pdb 'C:\DriverProject\x64\Debug\Example.pdb' `
    --source 'C:\DriverProject' --note 'Testando correção da corrida de cancelamento'
$before = klay status | ConvertFrom-Json
$previousCrash = $before.latest.crashId
```

O comando arquiva os binários em `build_root`, calcula os hashes e publica `active-run.json`. Quando o source é um repositório Git, registra a revisão e se havia modificações locais. O klay não compila nem carrega o driver e não copia o código-fonte. Preserve o source da build para comparar as linhas corretas. O manifesto registra a intenção do teste; confirme no KD o módulo carregado e a correspondência do PDB.

## Aguardar e ler o crash

Mantenha `klay watch` ou `Start-Klay.ps1` em execução. Depois de iniciar o teste do driver:

```powershell
if ($previousCrash) {
    klay wait --after $previousCrash --timeout 600 --require-analysis
} else {
    klay wait --timeout 600 --require-analysis
}
$waitExitCode = $LASTEXITCODE
```

`wait` acompanha `latest.json`; ele precisa de um monitor ativo. Com `--require-analysis`, retorna quando a análise do novo crash chega a `complete` ou `failed`. Sem essa opção, pode retornar apenas os metadados, enquanto o dump ainda está sendo coletado.

| Código de saída | Significado |
| --- | --- |
| `0` | Crash observado; com `--require-analysis`, análise concluída. |
| `1` | Falha de análise ou erro operacional; leia a saída e os relatórios disponíveis. |
| `2` | Tempo esgotado. Isso não prova que ocorreu um crash. |

Localize os arquivos pelos caminhos que o klay fornece:

```powershell
$latest = Get-Content (Join-Path $config.runtime_root 'latest.json') -Raw | ConvertFrom-Json
$latest | Format-List
if ($latest.metadataPath) { Get-Content -LiteralPath $latest.metadataPath -Raw }
if ($latest.analysisPath) { Get-Content -LiteralPath $latest.analysisPath -Raw }
```

No diretório `latest.crashDirectory`:

| Arquivo | Conteúdo |
| --- | --- |
| `crash.json` | Código, quatro parâmetros, boot, evento de origem e build selecionada. |
| `event.xml` / `system-events.json` | Evidências dos eventos do Windows. |
| `memory.dmp` | Dump binário para o debugger. |
| `ready.json` | Marcador de publicação concluída, tamanho e SHA-256 do dump. |
| `analysis.txt` | Saída completa do KD, stack, módulos e símbolos. |
| `analysis.json` | Estado, resumo extraído, timestamps e erro quando houver. |
| `analysis.commands.txt` | Comandos utilizados pelo KD. |

Estados: `no_crash_observed`, `waiting_for_dump`, `pending`, `running`, `complete` e `failed`. `complete` indica que o KD terminou e passou pelas verificações do klay; a conclusão sobre a causa ainda depende da análise técnica.

## Investigar o driver

Leia `.bugcheck`, `!analyze -v`, `kv`, módulos e mensagens de símbolos no `analysis.txt`. Compare o código e os parâmetros com `crash.json`. O monitor verifica SHA-256 e tamanho antes da análise e rejeita divergência de código ou dos parâmetros quando o KD os fornece.

Confirme módulo, timestamp e PDB; use o source da build arquivada para localizar a função e a linha da stack. Examine o contrato da API, o IRQL, o tempo de vida dos objetos e a sincronização conforme o Bug Check observado. Um nome de módulo apontado pelo debugger é evidência a investigar. A ausência de PDB privado não demonstra que aquele driver causou o crash.

Reporte o `crashId`, código e nome do Bug Check, parâmetros, módulo, stack relevante, validade dos símbolos, build/revisão, evidência que sustenta a hipótese e próximo teste. Não atribua um dump antigo ao teste atual.

## Refazer a análise

`analyze` usa o mesmo lock do monitor. Para um monitor iniciado por `Start-Klay.ps1`, pare antes e reinicie depois:

```powershell
.\scripts\Stop-Klay.ps1
klay analyze '<crashId>'
.\scripts\Start-Klay.ps1
```

Se iniciou `klay watch` no terminal, encerre com Ctrl+C antes da reanálise e execute `klay watch` novamente depois.

Para comandos extras de diagnóstico, use um arquivo local que você revisou:

```powershell
klay analyze '<crashId>' --commands-file 'C:\KlayData\extra-commands.txt'
```

Faça esse comando enquanto o monitor estiver parado. A reanálise substitui os relatórios anteriores; preserve uma cópia antes se precisar comparar resultados.

## Quando falta evidência

Se o heartbeat parou, confira o processo do host, o estado da VM, VMware Tools, o share e a tarefa `Klay-Export`. Erros do host ficam em `runtime_root\host.log`; no guest, o exporter grava `C:\ProgramData\Klay\status.json` e preserva o spool até publicar o dump.

Se existe um Bug Check mas o dump não chega, leia `crash.json.error`, confirme pagefile ativo, configuração de dump, espaço disponível e `volmgr` 46/161 do boot atual. Após configurar pagefile e dump, reinicie e confira o próximo heartbeat. Alguns ambientes precisam de mais de um boot até o pagefile ficar disponível ao mecanismo de dump. Um evento antigo de `volmgr` não determina o estado atual.

Se a análise falhou, leia `analysis.json.error` e `analysis.txt`: confira integridade do dump, caminho do KD, timeout e símbolos. Um timeout do `wait` só limita a espera do cliente; a coleta e a análise podem continuar.

Dumps, logs, arquivos de build e caminhos de source devem ficar fora do Git. Compartilhe apenas trechos revisados. Testes que provocam um crash ou reiniciam a VM dependem da autorização do responsável pelo ambiente.
