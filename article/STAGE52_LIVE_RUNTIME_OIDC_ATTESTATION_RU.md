# Stage52 — live Open5GS runtime OIDC attestation

## Цель

Stage51 использовал независимый Render runtime oracle, но этот oracle не был самим живым Open5GS NF. Stage52 переносит runtime-root к реально запущенному Open5GS NSSF и связывает challenge-response runtime-agent с provider-issued GitHub Actions OIDC workload identity. Внешний verifier работает на Render и независимо проверяет OIDC JWT и Ed25519 signature агента.

## Экспериментальная схема

- Open5GS v2.7.6 собирается заново в GitHub Actions.
- В live-контейнере запускаются NRF, SCP и NSSF.
- NSSF реально регистрируется в NRF; его текущий NFProfile извлекается через HTTP/2 discovery.
- Отдельный runtime-agent запускается в sidecar-контейнере с общим PID namespace с live Open5GS container.
- Agent генерирует эфемерный Ed25519 key и по challenge измеряет:
  - PID NSSF;
  - runtime `nfInstanceId` из native witness file;
  - SHA-256 исполняемого файла `open5gs-nssfd`;
  - SHA-256 cmdline/cgroup;
  - boot-id fingerprint;
  - direct SBI TCP reachability.
- GitHub Actions OIDC token запрашивается с custom audience `stage52-runtime:<SHA256(agent-public-key)>`.
- Внешний Render verifier проверяет RS256 подпись GitHub OIDC JWT по GitHub JWKS, issuer/audience/repository/ref/SHA, затем Ed25519 подпись runtime evidence и соответствие live NRF UUID, executable hash, challenge, process liveness и SBI reachability.

## Подтверждённый запуск

GitHub Actions run: 40702723583, conclusion: success.

- Honest live NSSF attestation: accepted.
- Replay ранее подписанного runtime response под новым challenge: rejected (`evidence_challenge`).
- Изменение executable hash без новой Ed25519 подписи: rejected (`agent_signature`, `evidence_exe_hash`).
- После реальной остановки NSSF verifier отклонил evidence: process_alive=false, SBI unreachable, UUID/executable absent.
- После реального рестарта NSSF зарегистрировался снова и новая runtime attestation была accepted.
- Runtime UUID изменился при рестарте.
- Initial UUID SHA-256: `29b70f95d7085df1a1f11cc86ca1c55348d91ffecc7cb5bca9df4b2e7bc3b8c1`.
- Restarted UUID SHA-256: `053dccc51a0c42d258048e0923c5db400cee67c6178e759ec58068214d49ab46`.
- NSSF executable SHA-256: `0e89cd75ff214a2f5e3f52c212e58befb129c457f8c07cc7a3146303c1bca65d`.
- Agent public-key SHA-256: `444ee1f8a6ee42f27455f760ea937db8c2c20160f5f517c72bd6b549b1a49459`.
- GitHub OIDC issuer: `https://token.actions.githubusercontent.com`.
- OIDC audience was bound to the agent key hash.
- OIDC repository/ref/commit SHA were independently validated by Render.
- Evidence artifact: `stage52-live-runtime-oidc-evidence`, ID 12821789130.
- Artifact ZIP SHA-256: `d19861b2125b412372d8dca48162429a42c7d7d6a4d566b070b644a685cbb965`.

## Научная интерпретация

В отличие от Stage51, runtime evidence Stage52 получено непосредственно из PID namespace живого Open5GS NSSF и сопоставлено с одновременно доступным SBI endpoint и реально зарегистрированным в NRF `nfInstanceId`. Ключ агента связан с provider-issued workload identity конкретного GitHub Actions run посредством custom OIDC audience, а проверка выполняется на независимом Render host.

Это существенно сильнее статического внешнего oracle и обычного process witness, однако GitHub OIDC не является TPM/TEE hardware attestation. Он удостоверяет workflow job и его claims; если весь runner вместе с agent и OIDC-capability скомпрометирован, злоумышленник потенциально может создать новый ключ и запросить OIDC token с новой audience. Поэтому Stage52 подтверждает live process binding при честном runner/agent boundary, но не доказывает аппаратную неподменяемость процесса.

## Следующая граница

Для закрытия последнего уровня требуется hardware-backed workload identity: TPM quote, confidential-VM attestation или TEE-attested key, где приватный ключ доступен только измеренному runtime. Это нельзя честно заменить одним GitHub OIDC token.
