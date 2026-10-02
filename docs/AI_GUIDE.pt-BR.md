# Usando o klay com outra IA

Depois que a VM reinicia, o klay coloca o dump e os relatórios do crash no host. Este guia mostra como acompanhar um teste e usar esses arquivos para investigar o driver.

## Antes de começar

Confira a instalação no [README](../README.md) e abra a configuração do monitor. O caminho padrão é `%LOCALAPPDATA%\Klay\config.json`. Se usar outro arquivo, passe `--config 'C:\Caminho\config.json'` antes do comando e `-Config` aos scripts do host. Use a mesma configuração para o monitor e os comandos do teste.

Os exemplos usam `klay` no PATH. Com o ambiente virtual do README, ative o ambiente ou escreva `.\.venv\Scripts\klay.exe`. Execute os scripts a partir da pasta do projeto.

```powershell
$config = Get-Content "$env:LOCALAPPDATA\Klay\config.json" -Raw | ConvertFrom-Json
klay status
```

`status` lê a última informação gravada pelo monitor. Execute novamente após alguns segundos: `status.hostTimeUtc` deve avançar. Confira estes campos:

- `status.guestHeartbeatAgeSeconds`: idade do heartbeat do guest.
- `status.guestReachability`: `online` com heartbeat recente; `unknown` quando não há informação recente.
- `status.rebootRequired`: reinício pendente após a instalação.
- `status.currentBootDumpErrors`: eventos `volmgr` 46/161 desde o boot atual.
- `status.guestHeartbeat.pagefiles`: pagefiles ativos após o reinício.
- `latest.crashId` e `latest.analysisState`: último crash observado e andamento da análise.

Se o heartbeat estiver antigo, confira a VM e a pasta compartilhada. A cópia de um dump grande também pode atrasar essa atualização. Para saber se houve um Bug Check no teste atual, você precisa de um `crashId` novo com o evento correspondente.

## Antes de testar uma build

Use o `.sys` e o `.pdb` produzidos pela mesma compilação:

```powershell
klay arm --driver 'C:\DriverProject\x64\Debug\Example.sys' `
    --pdb 'C:\DriverProject\x64\Debug\Example.pdb' `
    --source 'C:\DriverProject' --note 'Testando correção da corrida de cancelamento'
$before = klay status | ConvertFrom-Json
$previousCrash = $before.latest.crashId
```

`arm` copia os binários para `build_root`, calcula os hashes e grava `active-run.json`. Se `--source` apontar para um repositório Git, também registra a revisão e se havia alterações locais.

Compile o driver antes de executar `arm`; depois, carregue o `.sys` selecionado pelo fluxo do seu projeto. Preserve o código-fonte dessa build: o klay registra seu caminho, mas os arquivos continuam lá. Quando ler o relatório, confira se o módulo carregado e o PDB correspondem aos arquivos que você selecionou.

## Espere um crash novo

Deixe o monitor rodando com `klay watch` ou `Start-Klay.ps1`. Depois de iniciar o teste do driver, espere um crash diferente daquele que já estava em `latest.json`:

```powershell
if ($previousCrash) {
    klay wait --after $previousCrash --timeout 600 --require-analysis
} else {
    klay wait --timeout 600 --require-analysis
}
$waitExitCode = $LASTEXITCODE
```

`wait` acompanha `latest.json`, que o monitor atualiza. Com `--require-analysis`, a espera termina quando a análise chega a `complete` ou `failed`. Se omitir essa opção, o comando pode retornar assim que houver metadados, enquanto o dump ainda está sendo copiado.

| Código de saída | Significado |
| --- | --- |
| `0` | Crash observado; com `--require-analysis`, análise concluída. |
| `1` | Falha de análise ou erro operacional; leia a saída e os relatórios disponíveis. |
| `2` | A espera terminou sem um novo resultado que atendesse aos critérios do comando. |

## Abra os relatórios

Leia os caminhos em `latest.json`:

```powershell
$latest = Get-Content (Join-Path $config.runtime_root 'latest.json') -Raw | ConvertFrom-Json
$latest | Format-List
if ($latest.metadataPath) { Get-Content -LiteralPath $latest.metadataPath -Raw }
if ($latest.analysisPath) { Get-Content -LiteralPath $latest.analysisPath -Raw }
```

No diretório `latest.crashDirectory`:

| Arquivo | Conteúdo |
| --- | --- |
| `crash.json` | Código do Bug Check, quatro parâmetros, boot, evento de origem e build selecionada. |
| `event.xml` / `system-events.json` | Evento do crash e outros eventos recentes do Windows. |
| `memory.dmp` | Dump binário para o debugger. |
| `ready.json` | Marcador de publicação concluída, tamanho e SHA-256 do dump. |
| `analysis.txt` | Saída completa do KD, stack, módulos e símbolos. |
| `analysis.json` | Estado, resumo extraído, timestamps e erro quando houver. |
| `analysis.commands.txt` | Comandos utilizados pelo KD. |

Sem um crash registrado, `analysisState` mostra `no_crash_observed`. Os estados de um crash são `waiting_for_dump`, `pending`, `running`, `complete` e `failed`; algumas etapas podem terminar entre duas consultas. Em `complete`, o KD terminou e o resultado passou pelas verificações do klay. Leia a stack e os símbolos para entender a causa.

## Investigar o driver

Comece pela saída de `.bugcheck`, `!analyze -v` e `kv` em `analysis.txt`. Compare o código e os parâmetros com `crash.json`. O monitor já verifica tamanho e SHA-256 do dump e rejeita divergências entre o evento e o resultado do KD, incluindo os parâmetros quando o debugger os fornece.

Confira módulo, timestamp e PDB antes de procurar a função e a linha no código-fonte. Use a versão do código que gerou a build selecionada. A partir da stack e do Bug Check, investigue o ponto de falha: IRQL, tempo de vida de objetos, sincronização ou contrato da API, conforme o caso.

O módulo apontado pelo debugger ajuda a começar a investigação. Confirme a hipótese com a stack e o código. Se faltar PDB privado, registre a limitação e evite atribuir uma linha ou função que o relatório não mostra.

Ao relatar o problema, inclua o `crashId` e a build/revisão. Mostre o código e o nome do Bug Check, os parâmetros e o trecho da stack que sustenta a hipótese. Diga se os símbolos estão corretos e qual teste deve confirmar a correção.

## Rodar o KD novamente

Pare o monitor antes de usar `analyze`, pois os dois usam o mesmo lock. Se você iniciou pelo script:

```powershell
.\scripts\Stop-Klay.ps1
klay analyze '<crashId>'
.\scripts\Start-Klay.ps1
```

Se iniciou `klay watch` no terminal, pare com Ctrl+C e execute `klay watch` novamente depois da análise.

Para comandos extras de diagnóstico, use um arquivo local que você revisou:

```powershell
klay analyze '<crashId>' --commands-file 'C:\KlayData\extra-commands.txt'
```

A reanálise substitui os relatórios anteriores. Faça uma cópia antes se precisar comparar as saídas.

## Quando algo falha

Se o heartbeat parou, confira se o processo do host está rodando. No guest, verifique VMware Tools, o acesso ao share e a tarefa `Klay-Export`. Procure erros em `runtime_root\host.log` no host e em `C:\ProgramData\Klay\status.json` no guest. O dump fica no spool local até a publicação terminar.

Se existe um evento de Bug Check mas falta o dump, leia `crash.json.error`. Confira o pagefile ativo, a configuração de dump, o espaço disponível e os eventos `volmgr` 46/161 do boot atual. Depois de mudar pagefile ou dump, reinicie e confira o próximo heartbeat. Na VM usada no teste original, foi necessário mais um boot para o pagefile ficar disponível ao mecanismo de dump. Considere os eventos do boot atual ao verificar se isso foi resolvido.

Se a VM usa UWF, confira também se ele protege o volume do pagefile e descarta os arquivos da instalação após reiniciar. A [Microsoft documenta que o UWF desativa pagefiles na primeira ativação](https://learn.microsoft.com/en-us/windows/configuration/unified-write-filter/uwf-filterenable), e [pagefiles não aceitam exclusões de arquivo](https://learn.microsoft.com/en-us/windows/configuration/unified-write-filter/uwf-volumeaddexclusion). No teste do klay, o filtro foi desligado na VM de desenvolvimento antes da instalação. O instalador e `Restore-Guest.ps1` não alteram UWF.

Se o KD falhou, leia `analysis.json.error` e `analysis.txt`. O erro pode apontar para integridade do dump, caminho do debugger, timeout ou símbolos. Se apenas `wait` terminou por timeout, confira o estado novamente: o monitor continua coletando e analisando.

Guarde dumps, logs e arquivos de build fora do Git. Revise os trechos que precisar compartilhar. Combine com o responsável pela VM antes de provocar um crash ou reiniciá-la.
