# Usando o klay com outra IA

Depois que a VM reinicia, o klay coloca o dump e os relatórios do crash no host. Este guia mostra como acompanhar um teste, separar evidências de hipóteses e usar os arquivos para investigar o driver. O JSON ajuda na triagem; `analysis.txt`, `event.xml`, o dump e os binários preservados permitem conferir a origem de cada conclusão.

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
- `status.guestHeartbeat.systemDriveFreeBytes`: espaço livre no volume do Windows quando o heartbeat foi coletado.
- `status.guestHeartbeat.observedBuild`: último manifesto de build reconhecido pelo guest; confira `buildId` e `firstObservedAtUtc` antes do teste.
- `status.guestHeartbeat.selectionProtocol`: capacidade do exporter; `immutable_v1` identifica a implementação nova. A fonte efetivamente lida fica em `observedBuild.selectionProtocol` e `selectionRecord`.
- `status.guestHeartbeat.buildObservationError`: erro ao observar o manifesto, quando houver.
- `status.guestHeartbeat.environment`: contexto observado do Windows e de algumas defesas, com horário próprio de coleta.
- `latest.crashId` e `latest.analysisState`: último crash observado e andamento da análise.

Se o heartbeat estiver antigo, confira a VM e a pasta compartilhada. A cópia de um dump grande também pode atrasar essa atualização. Para saber se houve um Bug Check no teste atual, você precisa de um `crashId` novo com o evento correspondente. Reinício, perda de WinRM e evento Kernel-Power 41 com código zero não bastam para afirmar que houve BSOD.

## Antes de testar uma build

Use o `.sys` e, quando disponível, o `.pdb` produzido pela mesma compilação:

```powershell
$armed = klay arm --driver 'C:\DriverProject\x64\Debug\Example.sys' `
    --pdb 'C:\DriverProject\x64\Debug\Example.pdb' `
    --source 'C:\DriverProject' --note 'Testando correção da corrida de cancelamento' | ConvertFrom-Json
$before = klay status | ConvertFrom-Json
$previousCrash = $before.latest.crashId
```

`arm` copia os binários para `build_root`, calcula os hashes, guarda `build.json` e publica um registro imutável em `shared_root\build-selections\YYYYmmddTHHMMSSffffffZ_<buildId>.json`. Se `--source` apontar para um repositório Git, também registra a revisão e se havia alterações locais. O PDB é opcional: omita `--pdb` quando só tiver o `.sys`, e mantenha a ausência de símbolos privados explícita na investigação.

O manifesto usa `schema=1`, `selectionProtocol=immutable_v1` e `selectionRecord` com o nome exato do arquivo. `active-run.json` é apenas o ponteiro de compatibilidade. Se HGFS mantiver esse arquivo bloqueado, o novo registro pode ser publicado com sucesso e `arm` retornar `legacyPointerUpdated=false` e `compatibilityWarning`; um guest antigo pode continuar lendo a seleção anterior. O retorno de `arm` não comprova reconhecimento do guest. Atualize o exporter e espere o ack da seleção nova antes de carregar o driver.

Quando as identidades estiverem disponíveis, `arm` compara o GUID e a idade do CodeView do `.sys` com os do PDB e rejeita divergências. A confirmação entre esses dois arquivos não prova que a VM carregou esse `.sys`. O nome do driver e o fato de uma build estar armada também não provam essa associação.

Compile o driver antes de executar `arm`; depois, carregue o `.sys` selecionado pelo fluxo do seu projeto. Preserve o código-fonte dessa build: o klay registra seu caminho, mas os arquivos continuam lá. Se `sourceDirty` for verdadeiro, o commit sozinho não reproduz a compilação; guarde as alterações e os parâmetros do build junto ao teste. Quando ler o relatório, confira se o módulo carregado e o PDB correspondem aos arquivos selecionados.

Antes de provocar a falha, espere um heartbeat recente em que `status.guestHeartbeat.observedBuild.buildId` coincida com `$armed.buildId`. Para o protocolo novo, confira a capacidade `status.guestHeartbeat.selectionProtocol=immutable_v1` e a observação com `selectionProtocol=immutable_v1` e `selectionRecord` igual a `$armed.selectionRecord`. O exporter consulta a seleção a cada ciclo; a cópia de outro dump ou a indisponibilidade do share pode atrasar esse reconhecimento. Se o driver cair antes de o guest observar a build, a associação pode permanecer desconhecida. O reconhecimento confirma intenção de teste, não que o Windows carregou o arquivo.

O guest escolhe o maior nome cronológico válido entre os JSON do diretório, depois verifica tamanho de até 64 KiB e concordância de schema, protocolo, nome, ID e horário. Mais de 1.024 JSON interrompem a leitura com erro. Um registro selecionado inválido não faz fallback para uma build anterior. Só há leitura legada quando o diretório não existe ou está sem JSON. Arquive manualmente seleções antigas fora do share, preservando a atual e as necessárias para os testes; não altere o conteúdo/nome para contornar uma falha.

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
if ($latest.analysisJsonPath) { Get-Content -LiteralPath $latest.analysisJsonPath -Raw }
if ($latest.analysisPath) { Get-Content -LiteralPath $latest.analysisPath -Raw }
```

No diretório `latest.crashDirectory`:

| Arquivo | Conteúdo |
| --- | --- |
| `crash.json` | Código do Bug Check, quatro parâmetros, boot, evento de origem e build selecionada. |
| `event.xml` / `system-events.json` | Evento do crash e outros eventos recentes do Windows. |
| `event-fallback.xml` / `wer-upgrade-event.xml` | Quando presentes, evento original preservado após upgrade para WER e candidato WER cuja tentativa de upgrade foi recusada. |
| `memory.dmp` | Dump binário para o debugger. |
| `ready.json` | Marcador de publicação concluída, tamanho e SHA-256 do dump. |
| `analysis.txt` | Saída completa do KD, stack, módulos, símbolos e avisos. |
| `analysis.json` | Estado, evidências extraídas, qualidade dos símbolos, limitações, timestamps e erro quando houver. |
| `analysis.commands.txt` | Comandos utilizados pelo KD. |

Sem um crash registrado, `analysisState` mostra `no_crash_observed`. Os estados de um crash são `waiting_for_dump`, `pending`, `running`, `complete` e `failed`; algumas etapas podem terminar entre duas consultas. Em `complete`, o KD terminou e o resultado passou pelas verificações do klay. Esse estado não significa que a causa foi provada nem que o PDB privado carregou. Leia a qualidade dos símbolos, as limitações e a stack antes de atribuir o problema ao código.

Os campos adicionais de `analysis.json` ajudam a localizar a evidência sem substituir o relatório completo:

| Campo | Leitura correta |
| --- | --- |
| `bugcheckParameterDetails` | Valores e descrições dos argumentos extraídos da saída de `!analyze`; não são uma interpretação própria do klay. |
| `stackEvidence` / `debuggerWarnings` | Trechos literais com `line` indicando a linha de `analysis.txt`. Alguns avisos têm `kind=dump_memory` ou `symbol_loading`; leia também a tabela de erros de símbolos. As listas são limitadas; confira `stackEvidenceTruncated` e `debuggerWarningsTruncated`. |
| `registerEvidence` / `faultingInstruction` | Linhas de registradores e trecho `FAULTING_IP` ou `IP_IN_PAGED_CODE` emitidos pelo KD. Confira `registerEvidenceTruncated` e o contexto/trap frame antes de interpretar esses valores. |
| `faultingThread`, `trapFrame`, `contextRecord`, `exceptionRecord` | Campos que KD emitiu quando disponíveis. Ausência do campo significa ausência de evidência extraída. |
| `stackCommand` | Sugestão textual emitida pelo debugger; o klay a preserva como evidência e não a executa automaticamente. |
| `eventConsistency` | Integridade do dump e comparação com o evento. `not_available` e `not_reported_by_debugger` deixam explícita uma comparação que não pôde ser feita. |
| `systemEvidence` | Trechos de `!sysinfo machineid`, `!sysinfo smbios` e `!cpuinfo` quando disponíveis; não é um atestado de segurança. Confira `systemEvidenceTruncated`. |
| `symbolQuality.privateSymbolsProvided` | Um PDB foi fornecido no arquivo local da build; isso sozinho não prova carregamento no KD. |
| `symbolQuality.pdbIdentityMatch` | `matched`, `unverified` ou `not_provided` para a comparação dos arquivos armados. |
| `symbolQuality.loadedSymbols` | O trecho do módulo relata `private`, `pdb`, `export`, `missing` ou `unverified`. `pdb` não afirma que os símbolos sejam privados. |
| `symbolQuality.moduleMetadataMatch` | `matched`, `mismatch` ou `unverified` para timestamp e tamanho da imagem carregada versus arquivo arquivado. Mesmo `matched` não é um hash do binário carregado. |
| `symbolQuality.moduleEvidence` / `warnings` | Saída do módulo selecionado e avisos que sustentam a avaliação; leia qual módulo cada aviso cita e confira `moduleEvidenceTruncated`. |
| `buildEvidence` | Identidades e hashes da build local verificada, quando encontrada; não comprova instalação na VM. |
| `evidencePaths`, `elapsedSeconds`, `exitCode` | Caminhos dos artefatos e dados da execução de KD; o tempo não inclui necessariamente o teste, reboot ou exportação do guest. |
| `limitations` | Limitações explícitas da análise, da associação com a build e dos dados disponíveis. |

`symbolQuality.state` resume essa avaliação como `private_symbols_loaded`, `pdb_symbols_loaded`, `export_symbols_only`, `no_private_symbols`, `unverified` ou `degraded`. Em `degraded`, confira os avisos antes de decidir se afetam Windows, seu driver ou outro módulo. Relatórios antigos podem não conter esses campos; trate a qualidade como desconhecida e leia `analysis.txt`.

## Confirmar a associação do dump e da build

`bootTimeUtc` identifica o boot após o crash, usado no `crashId`. `reportTimeUtc` vem do evento do Windows e pode ser posterior ao boot; não use esse horário como o instante exato da falha. Quando disponível, `dumpEvidence.header.systemTimeUtc` é o horário escrito no cabeçalho do dump.

O exporter aceita cabeçalhos AMD64 de formato kernel (`PAGEDU64`), compara código e quatro parâmetros com o evento e exige que o horário esteja entre o boot anterior e o atual, com tolerância de cinco segundos. Os limites vêm de `StartTime` nos eventos Kernel-General 12, ordenados pelo ID do registro. O último precisa concordar com o boot atual informado por CIM em até 120 segundos; divergências maiores tornam o limite desconhecido. `previousBoot` registra o limite anterior e também `currentBootTimeUtc` e `currentBootEventRecordId`. O horário de Kernel-General pode preceder o de CIM; use os limites registrados, sem substituir um pelo outro. `dumpEvidence` conserva o método, cabeçalho, origem do evento, caminho e horário da cópia, além do SHA-256. Um `MEMORY.DMP` antigo com timestamp de arquivo alterado não basta para passar essas verificações.

Para associar o evento ao boot atual, o detector usa o limite Kernel-General quando disponível: o horário deve ser posterior ao início menos cinco segundos, e `EventRecordId` deve ser maior que `currentBootEventRecordId`. Um evento de outro boot dentro da tolerância de horário não basta para caracterizar um crash novo.

WER 1001 pode chegar depois do fallback Kernel-Power 41. Em uma captura já `ready`, o exporter revalida o cabeçalho salvo contra código, quatro parâmetros e janela de boot do candidato antes de trocar a origem. `reportUpgrade.state=rejected` conserva o relatório/evento anterior e informa `error` e `candidate`; leia também `wer-upgrade-event.xml`. Em `accepted`, confira a origem anterior preservada em `event-fallback.xml` e a nova proveniência em `dumpEvidence`. `pending_dump_validation` registra uma troca ocorrida antes da validação do dump; ela ainda depende do guard de captura. Ausência de cabeçalho em um relatório legado impede um upgrade seguro. Não misture parâmetros do candidato rejeitado com a stack do dump aceito.

`buildCorrelation.state = observed_before_crash` significa que o guest observou o manifesto selecionado antes do horário validado do dump. `firstObservedAtUtc`, `armedAtUtc`, `crashTimeUtc` e `manifestSha256` permitem conferir essa relação; `selectionProtocol` e `selectionRecord` identificam sua origem efetiva. Em `unknown`, não assuma que o driver arquivado corresponde ao teste. `buildObservations` registra observações recentes e é limitado a 64 entradas. Relatórios antigos sem essa correlação não ganham prova de timing pelo simples fato de ter `armedBuild` preenchido.

Se a captura foi retomada em outro boot, `captureRecovery` registra esse reinício e o boot original do relatório. O klay continua usando os limites originais para validar o dump. Confira essas datas antes de relacionar o resultado à última sessão de teste.

## Ler o ambiente sem confundir os momentos

O heartbeat inclui `environment` com `observedAtUtc` e origem da observação. O exporter renova esse contexto no próximo ciclo após 60 segundos. Uma cópia demorada ou falha de consulta pode atrasar a atualização; confira o horário do próprio ambiente, além do horário do heartbeat.

| Campo do ambiente | O que foi observado |
| --- | --- |
| `os.buildNumber` / `os.ubr` | Build base e revisão de atualização; use ambos para identificar uma compilação como `26200.8655`. |
| `os.displayVersion`, `editionId`, `architecture` | Versão de lançamento, edição e arquitetura reportadas naquele ambiente. |
| `secureBoot.enabled` / `error` | Resultado da consulta de Secure Boot, ou null e erro quando não foi possível consultá-lo. |
| `deviceGuard.virtualizationBasedSecurityStatus` | Estado de VBS reportado por `Win32_DeviceGuard`. |
| `deviceGuard.securityServicesConfigured` / `securityServicesRunning` | Listas numéricas de serviços configurados e em execução; configuração não equivale a execução. Consulte a [definição Microsoft](https://learn.microsoft.com/en-us/windows/security/hardware-security/enable-virtualization-based-protection-of-code-integrity). |
| `defender.antivirusEnabled`, `realTimeProtectionEnabled`, `isTamperProtected` | Estados reportados pelo provedor do Defender; null significa não observado, não desligado. |
| `deviceGuardError` / `defenderError` | Falha na consulta, quando houver; não transforme erro de coleta em conclusão sobre a defesa. |

`osVersion` na análise preserva o literal emitido pelo KD; não substitui EditionID, DisplayVersion, build/UBR do guest ou `winver`. No teste de 25H2, KD informou `10.0.26100.1` enquanto os contextos do guest indicavam Education 25H2 `26200.8655`. A Microsoft documenta um core comum entre 24H2 e 25H2; registre as duas origens sem converter o literal de KD em uma conclusão de downgrade. [KB5054156](https://support.microsoft.com/en-us/servicing/os/windows/docs/2025/02/kb5054156-feature-update-to-windows-11-version-25h2-by-using-an-enablement-package).

Em `crash.json`, `preCrashObservation` preserva a última observação local disponível do boot que caiu, com horário anterior ao dump validado. O exporter associa `kernelBootTimeUtc` ao limite Kernel-General anterior, com tolerância de cinco segundos. Ela inclui `environment`, reconhecimento da build, pagefiles e configurações de dump. Confira `preCrashObservation.timeUtc`, `kernelBootTimeUtc`, `bootTimeUtc` e `environment.observedAtUtc`: a defesa pode ter mudado depois da consulta. Se esse registro estiver ausente, o estado anterior permanece desconhecido.

`postBootEnvironment` contém o primeiro contexto observado após o boot de recuperação. Ele ajuda a verificar como a VM voltou, mas não substitui a observação anterior. O histórico local é limitado a 64 boots e só coleta quando o exporter está executando; o relay não registra continuamente todas as mudanças de segurança.

## Investigar o driver

Comece pela saída de `.bugcheck`, `!analyze -v` e `kv` em `analysis.txt`. Compare o código e os parâmetros com `crash.json`. O monitor já verifica tamanho e SHA-256 do dump e rejeita divergências entre o evento e o resultado do KD, incluindo os parâmetros quando o debugger os fornece. SHA-256 confirma a integridade da transferência, não a associação causal entre o driver e a falha.

Leia primeiro a definição oficial do [código do Bug Check](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-code-reference2). Os quatro argumentos têm significados diferentes conforme o código; alguns valores são endereços, outros são IRQL, flags ou códigos de violação. Use as descrições emitidas por `!analyze -v` e confirme a interpretação na referência, em vez de tratar todo argumento como ponteiro.

Confira módulo, timestamp, tamanho da imagem e PDB antes de procurar a função e a linha no código-fonte. Use a versão do código que gerou a build selecionada. A partir da stack e do Bug Check, investigue IRQL, tempo de vida de objetos, sincronização, buffers ou contrato da API. Um driver presente na stack pode estar recebendo dados já corrompidos de outro componente.

`MODULE_NAME`, `IMAGE_NAME`, `FAILURE_BUCKET_ID` e `Probably caused by` são pistas do debugger. O processo ativo também pode ser apenas o contexto da thread, sem ter causado o defeito. Não atribua a culpa a `ntoskrnl.exe` só porque o kernel detectou a inconsistência. Corrupção de memória pode produzir uma falha longe de quem gravou o dado incorreto.

Se faltar PDB privado, registre a limitação e evite inventar uma linha, tipo ou variável local. Símbolos públicos do Windows não substituem os símbolos do driver. Mesmo com PDB compatível, otimização e páginas ausentes podem impedir a leitura de variáveis. Preserve mensagens como `Unable to read`, avisos de símbolos e trap frames incompletos no relatório; ausência de dados não demonstra que o objeto estava válido ou que o caminho não executou.

Para aprofundar, escolha comandos a partir de endereços presentes neste dump. Os exemplos abaixo são consultas no KD; substitua os marcadores antes de usá-los em `--commands-file`:

| Pergunta | Comandos e condições |
| --- | --- |
| Qual binário e quais símbolos foram carregados? | `lmvm MeuDriver`, `.sympath`, `!sym noisy` e `.reload /f MeuDriver.sys`; confira também os avisos e o arquivo PDB selecionado. |
| Qual thread e contexto falharam? | `!thread <thread>`, `kv`, `r`; use `.trap <trap-frame>` ou `.cxr <context-record>` somente quando `!analyze` identificar esse registro, e execute `kv` novamente nesse contexto. |
| Houve exceção com registro disponível? | `.exr <exception-record>`; confronte a exceção, a instrução e o acesso com o Bug Check. |
| O endereço pertence a uma alocação de pool? | `!pool <endereco>`; o dump precisa conter as páginas e os metadados. Um bloco liberado ou corrompido pede investigação do tempo de vida e do responsável pela escrita. |
| Um IRP ou dispositivo aparece nos argumentos? | `!irp <irp> 1`, `!devstack <device-object>`; verifique propriedade, cancelamento, completion e transições da stack. |
| Driver Verifier capturou a violação? | `!verifier`, `!verifier 3 MeuDriver.sys`; detalhes dependem das opções e do driver verificado. Use `!deadlock` quando houver dados de detecção de deadlock. |
| Há espera ou estado sistêmico relevante? | `!process 0 0`, `!thread <thread>`, `!locks`, `!vm`; investigue as threads e objetos relevantes sem confundir uma thread em espera com a origem da falha. |

O relatório padrão já coleta vários desses contextos. Consulte `analysis.commands.txt` para saber o que rodou. Extensões `!blackboxbsd`, `!blackboxpnp` e `!blackboxntfs` só ajudam quando seus dados estão no dump; a falta deles não invalida por si só uma análise. Confira as referências de [análise de Bug Check](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/blue-screen-data), [IRP](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-irp), [device stack](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-devstack) e [Verifier](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-verifier).

## Entregar uma conclusão à IA ou ao desenvolvedor

Use uma estrutura curta que permita auditar a hipótese:

1. Identifique `crashId`, versão do Windows observada, build armada, hash do driver e revisão do código. Registre qualquer associação incerta com o binário carregado.
2. Apresente código, nome e quatro argumentos do Bug Check com seus significados. Cite arquivos e linhas de `analysis.txt` para a stack, instrução, regra do Verifier ou contexto que sustentam a leitura.
3. Separe fatos observados, hipótese mais provável e alternativas ainda possíveis. Declare o estado dos símbolos e as páginas ou registros ausentes.
4. Proponha a menor mudança de código que explique o mecanismo da falha. Não trate um teste que deixou de cair uma vez como confirmação suficiente de uma corrida.
5. Defina como reproduzir e validar: entrada, ciclo de carga/descarga, concorrência, quantidade de repetições e opções do Verifier quando pertinentes. Preserve a configuração de segurança do teste.

Não declare assinatura, Secure Boot, HVCI ou Defender ativos a partir do simples sucesso da análise. O relay coleta algumas observações de segurança, sem emitir um atestado completo desses controles ou da assinatura do driver. Quando a configuração de segurança importar para a hipótese, cite o campo observado, sua origem e horário, e registre verificações adicionais separadamente. Uma defesa ativa depois do reinício não comprova que estava ativa no instante do Bug Check. Não preencha um estado desconhecido com uma verificação de outro boot.

## Dumps e debugging ao vivo

O klay usa análise offline do dump e preserva a configuração das defesas. Não habilita `bcdedit /debug`, test signing ou alterações de HVCI. A assinatura do driver não garante que ele esteja livre de bugs nem que seja compatível com integridade de memória. A [Microsoft recomenda testes com HVCI ativo](https://learn.microsoft.com/en-us/windows-hardware/test/hlk/testref/driver-compatibility-with-device-guard).

Automatic Memory Dump contém memória de kernel; buffers de usuário e outras páginas podem faltar. Se a hipótese depende desses dados, escolha um dump maior para o próximo teste, com pagefile e espaço suficientes. O klay não recupera páginas que Windows não escreveu. Veja [tipos de dumps](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/varieties-of-kernel-mode-dump-files) e [dimensionamento de pagefile](https://learn.microsoft.com/en-us/troubleshoot/windows-client/performance/how-to-determine-the-appropriate-page-file-size-for-64-bit-versions-of-windows).

Breakpoints e execução passo a passo antes da falha exigem uma sessão de kernel debugging ao vivo. Esse fluxo não faz parte do relay: muda opções de boot e pode exigir mudanças em Secure Boot ou BitLocker, conforme a [documentação de KDNET](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-a-network-debugging-connection-automatically). Um debugger ativo também pode alterar o enforcement de assinatura; há uma [opção específica para preservá-lo](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/appendix-1--enforcing-kernel-mode-signature-verification-in-kernel-debugging-mode). Não migre o teste para KD ao vivo como correção automática de um dump incompleto.

## Usar Driver Verifier em um teste dirigido

O klay inclui a saída de `!verifier` na análise, mas não ativa o Verifier. Quando autorizado na VM de desenvolvimento, selecione o nome exato do driver, use uma janela de teste e preserve uma forma de recuperação:

```powershell
verifier /standard /driver MeuDriver.sys
verifier /bootmode oneboot
verifier /querysettings
```

A configuração acima vale no próximo boot; reinicie manualmente quando fizer parte do teste autorizado. `oneboot` limita a persistência ao próximo início do Windows. Para limpar configurações, use `verifier /reset` e reinicie. Evite `/all` como padrão: verificar drivers não relacionados pode reduzir os recursos disponíveis para o driver investigado e introduzir outras falhas.

Para uma execução de compatibilidade com HVCI, a opção [Code Integrity Checks](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/code-integrity-checking) usa `verifier /flags 0x02000000 /driver MeuDriver.sys`. Escolha as opções para aquele teste e confira `querysettings`; não suponha que um segundo comando preservou as flags do primeiro. Driver Verifier pode provocar BSOD ao detectar uma violação. Veja [orientação oficial](https://learn.microsoft.com/en-us/windows-hardware/drivers/devtest/driver-verifier).

## Rodar o KD novamente

Pare o monitor antes de usar `analyze`, pois os dois usam o mesmo lock. Se você iniciou pelo script:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Stop-Klay.ps1
klay analyze '<crashId>'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Start-Klay.ps1
```

Se iniciou `klay watch` no terminal, pare com Ctrl+C e execute `klay watch` novamente depois da análise.

Para comandos extras de diagnóstico, use um arquivo local que você revisou:

```powershell
klay analyze '<crashId>' --commands-file 'C:\KlayData\extra-commands.txt'
```

A reanálise substitui os relatórios anteriores. Faça uma cópia antes se precisar comparar as saídas.

## Quando algo falha

Se o heartbeat parou, confira se o processo do host está rodando. No guest, verifique VMware Tools, o acesso ao share e a tarefa `Klay-Export`. Procure erros em `runtime_root\host.log` no host e em `C:\ProgramData\Klay\status.json` no guest. O dump fica no spool local até a publicação terminar.

Se existe um evento de Bug Check mas falta o dump, leia `crash.json.error`. Confira o pagefile ativo, a configuração de dump, o espaço disponível e os eventos `volmgr` 46/161 do boot atual. O exporter também pode estar aguardando um limite de boot confiável, recusando um cabeçalho incompatível, ou rejeitando código, parâmetros ou horário divergentes. Minidumps não substituem o dump kernel AMD64 esperado. Não altere datas nem manifeste um arquivo antigo como se fosse o novo crash.

Depois de mudar pagefile ou dump, reinicie e confira o próximo heartbeat. Na VM usada no teste original, foi necessário mais um boot para o pagefile ficar disponível ao mecanismo de dump. Considere os eventos do boot atual ao verificar se isso foi resolvido. Uma captura pendente pode retomar depois de outro reboot, se o dump original ainda existir e passar pela correlação; um novo dump sobrescrevendo `MEMORY.DMP` pode tornar os dados anteriores irrecuperáveis.

Se a VM usa UWF, confira também se ele protege o volume do pagefile e descarta os arquivos da instalação após reiniciar. A [Microsoft documenta que o UWF desativa pagefiles na primeira ativação](https://learn.microsoft.com/en-us/windows/configuration/unified-write-filter/uwf-filterenable), e [pagefiles não aceitam exclusões de arquivo](https://learn.microsoft.com/en-us/windows/configuration/unified-write-filter/uwf-volumeaddexclusion). No teste do klay, o filtro foi desligado na VM de desenvolvimento antes da instalação. O instalador e `Restore-Guest.ps1` não alteram UWF.

Se o KD falhou, leia `analysis.json.error` e `analysis.txt`. O erro pode apontar para integridade do dump, caminho do debugger, timeout ou símbolos. Se apenas `wait` terminou por timeout, confira o estado novamente: o monitor continua coletando e analisando.

Guarde dumps, logs e arquivos de build fora do Git. Revise os trechos que precisar compartilhar. Combine com o responsável pela VM antes de provocar um crash ou reiniciá-la.
