# Stage39: закрытие экспериментальных границ Stage38

Stage39 не изменяет замороженный корпус и численные результаты Stage38. Это отдельный
воспроизводимый слой реализации и новых экспериментов GitHub Actions. Поэтому результаты
Stage39 не суммируются с 256 сценариями Stage38 и должны цитироваться как дополнительная
валидация.

## Итог по семи исходным пробелам

| № | Проблема | Состояние Stage39 | Что подтверждается |
|---|---|---|---|
| 1 | Oracle-эталон зависел от NRF | Существенно закрыто | Отдельная full-profile policy для 9 типов / 13 слотов, ECDSA-подпись policy, отрицательный tamper-test, KIE связывает policy digest |
| 2 | Registry poisoning / CVE-класс | Существенно закрыто | Реальная ложная регистрация в NRF, плюс live FQDN/service poisoning matrix: 18/18 защищённых случаев |
| 3 | Ложные тревоги определялись transition-plan | Существенно закрыто | Внешний подписанный orchestrator-event source, 5000 случайных событий, causal verifier без будущего состояния, сильные lifecycle-aware baselines |
| 4 | Узкие лабораторные условия | Существенно расширено | 13 live Open5GS процессов / 9 NF типов, 225 native mutations, 40 500 benign lifecycle events за 2 минуты, live mTLS discovery load |
| 5 | Future state / отсутствие real-time | Существенно закрыто | Нет post-reference из будущего; три latency clocks, включая onset timestamp из отдельного sidecar-controller |
| 6 | Witness не показывал информационного вклада | Закрыто экспериментальной абляцией | Identity: policy-only 0/36, witness-only 36/36, combined 36/36; service/FQDN наоборот зависят от policy |
| 7 | КИЕ не была частью исполняемого Nnrf пути | **Закрыто на уровне реализации** | KIE request/response переносится в schema-defined `NFProfile.customInfo`, проходит через нативный Open5GS `nnrf-nfm` heartbeat PATCH, сохраняется в NRF state и round-trip через NFM GET + Nnrf discovery; replay/stale/tamper отвергаются |

Оставшиеся границы перечислены в конце документа. Контейнер `NFProfile.customInfo` является
частью схемы NFProfile TS 29.510, однако содержимое KIE внутри него остаётся исследовательским
расширением и не объявляется новым стандартизованным 3GPP IE.

## 1. Независимый и подписанный oracle-policy

`stage39/full_profile_policy.json` задаёт полную разрешённую семантику независимо от
наблюдаемого NRF discovery response. Политика содержит 13 слотов и 9 типов NF:

- NSSF × 2;
- AUSF × 2;
- BSF × 2;
- UDM × 2;
- AMF;
- SMF;
- PCF;
- NRF;
- SCP.

Политика включает NF type, endpoint, FQDN и service semantics. Для live Open5GS используется
`stage39/live_open5gs/live_policy.json`.

В Actions политика подписывается отдельным EC private key. В Open5GS-контейнер передаются только
public key и detached signature. `live_probe.py` проверяет подпись до использования policy и
отдельно проверяет, что изменённый policy document с той же подписью отвергается. Digest policy
связывается с KIE.

Это обеспечивает независимость от NRF observation plane. При этом policy и код по-прежнему
управляются в одном GitHub repository/workspace, поэтому организационно независимый внешний
policy authority остаётся возможным усилением.

## 2. Registry poisoning и изменение полей живого NRF

Stage39 выполняет два класса live registry poisoning.

### Arbitrary registration

В живой NRF Open5GS регистрируется дополнительный NSSF-профиль. NRF отвечает HTTP 201, профиль
реально становится discoverable, а число NSSF в discovery увеличивается с 2 до 3. Независимая
policy отвергает профиль по неразрешённому endpoint. После DELETE чистое состояние
восстанавливается.

### FQDN/service poisoning существующих профилей

Для каждого discovery-visible типа отдельно проверяются FQDN и service-content:

- NSSF;
- AUSF;
- BSF;
- UDM;
- AMF;
- SMF;
- PCF;
- SCP;
- NRF.

Всего: **18/18 защищённых случаев**.

Для восьми внешних по отношению к NRF типов изменение реально записывается в live NRF registry,
становится видимым через discovery и обнаруживается policy: **16/16 applied-and-detected**.
После каждого случая профиль удаляется и регистрируется заново из сохранённого чистого состояния,
после чего policy снова возвращает clean.

Для собственного NRF self-profile Open5GS не разрешает внешний overwrite: обе попытки
FQDN/service изменения возвращают **HTTP 403 SELF Not allowed**. Эти два случая учитываются
отдельно как server-prevented, а не как detector-detected.

Таким образом live matrix различает предотвращение записи и обнаружение уже записанного
отравления.

## 3. Независимый lifecycle authorization вместо скрытого transition-plan

Добавлены:

- `research/stage39_external_scenarios.py`;
- `research/stage39_orchestration_eval.py`.

Отдельный generator process создаёт lifecycle intent со следующими полями:

- source ID;
- monotonic sequence;
- event ID;
- timestamp;
- nonce;
- stop/start/restart;
- target slot;
- policy SHA-256;
- допустимое transition window.

Событие HMAC-подписывается ключом orchestrator. Verifier проверяет MAC, policy binding,
freshness, sequence и nonce. Tampered event и replay отвергаются.

Labels атаки хранятся отдельно и не передаются detector API; они соединяются с решениями только
при расчёте метрик. Генератор мутаций реализован отдельно от `stage39_kie.mutate` и использует
отдельные случайные mutation tokens.

В одном blind-like CI прогоне обрабатывается 5000 событий. Типичный подтверждённый run содержит
около 1.4–1.5 тыс. атак и 3.5 тыс. benign events. Для `relational_signed_event` получено
TP=all attacks, FN=0, FP=0.

### Сильные baselines

Одновременно сравниваются:

- count/status;
- strict pre-snapshot;
- full pre-or-post snapshot;
- lifecycle-aware full policy без witness;
- lifecycle-aware full policy + witness;
- relational signed-event rule.

Ключевой научный результат этого сравнения: **равно выразительный lifecycle-aware full-policy
baseline также достигает recall 1.0 и FPR 0** в этом генераторе. Поэтому Stage39 не утверждает,
что слово «relational» само по себе даёт уникальное преимущество. Эксперимент показывает вклад
явной lifecycle authorization semantics, независимой policy и witness/provenance decomposition.

Strict snapshot и full pre/post при этом дают большое число FP на разрешённых переходах, а
count/status дополнительно пропускает часть атак.

## 4. Benign churn и более широкий workload

Создан `.github/workflows/stage39-churn.yml`.

PR validation выполняет 2 минуты wall-clock benign lifecycle churn. Подтверждённый run обработал
**40 500 подписанных lifecycle events** за 120.31 секунды:

- restart: 22 742;
- stop: 8 895;
- start: 8 863;
- false alerts: 0.

Каждый batch создаётся отдельным generator process с новым случайным seed. Future post-reference
не используется.

Workflow также поддерживает ручную длительность 1–360 минут, а scheduled run настроен на
**120 минут**. Наличие двухчасового workflow не должно цитироваться как двухчасовой
эксперимент, пока конкретный scheduled/manual run фактически не завершён.

Отдельно live Open5GS mTLS probe выполняет **300 параллелизованных discovery requests**
(concurrency 20) с новым TLS+h2 соединением на запрос. Подтверждено 0 transport/application
errors. Эта нагрузка проверяет SBI control plane, но не заменяет реальный UE registration/PDU
traffic.

## 5. Потоковый режим и измерение задержки

`StreamRelationalVerifier` не получает будущий post-reference. В causal CI выполнены
**39/39** случаев stop/start/restart для 13 слотов.

Для live native matrix используются три разных latency definition.

### Discovery request → alert

От начала локального discovery request до результата combined detector:

- sample count: 225;
- median **0.748 ms**;
- p95 **0.876 ms**;
- max **1.128 ms** в подтверждённом run.

### NRF mutation hook → alert

Timestamp записывается `CLOCK_MONOTONIC` непосредственно после изменения response внутри NRF:

- sample count: 225;
- median **0.390 ms**;
- p95 **0.484 ms**;
- max **0.538 ms** в подтверждённом run.

### External sidecar controller onset → alert

Отдельный container `external_attack_driver.py` ставит `CLOCK_MONOTONIC` timestamp
непосредственно перед передачей команды на конкретную live mutation. Core отвечает ack только
после detector decision:

- 225/225 команд подтверждены;
- median **1.925 ms**;
- p95 **2.921 ms**;
- max **3.795 ms**.

Эта третья метрика включает межконтейнерный handoff, discovery, mutation в NRF и detector.
Она намного ближе к end-to-end laboratory latency, но timestamp всё ещё принадлежит
контролируемому атакующему sidecar, а не произвольному внешнему злоумышленнику в реальной сети.

## 6. Формальная witness-ablation

Witness выполняется отдельным контейнером. Его private signing key не монтируется в контейнер
Open5GS. Источник:

`separate-container:/proc + direct-SBI + runtime-UUID-record`.

В live run собрано и проверено **13/13 runtime witness records**.

Для всех 225 native mutation cases вычисляются три решения:

- policy-only;
- witness-only;
- combined.

Получена следующая абляция:

| Семейство | cases | policy-only | witness-only | combined |
|---|---:|---:|---:|---:|
| identity replacement | 36 | **0** | **36** | 36 |
| endpoint substitution | 36 | 36 | 36 | 36 |
| service injection | 36 | 36 | **0** | 36 |
| FQDN substitution | 36 | 36 | **0** | 36 |
| NF-type substitution | 36 | 36 | 36 | 36 |
| identity + service | 36 | 36 | 36 | 36 |
| duplicate profile | 9 | 9 | 9 | 9 |

Это прямо показывает информационную комплементарность: UUID identity не выводится из независимой
full-profile policy и требует witness, тогда как FQDN/service semantics не выводятся из runtime
witness и требуют policy.

При наличии отдельно доверенного точного pre-snapshot часть identity-атак, конечно, можно
обнаружить и сравнением snapshot. Поэтому вклад witness относится прежде всего к независимому
provenance channel, а не к математической невозможности иных детекторов.

Оба контейнера остаются на одном GitHub runner/kernel; физически независимый host/TPM/TEE
эксперимент не заявляется.

## 7. Исполняемая КИЕ в нативном Nnrf_NFManagement пути

В `research/stage39_kie.py` реализованы `KIE_REQUEST`/`KIE_RESPONSE`, controller/subject ID,
монотонный cycle, timestamp, 128-bit nonce, policy digest, telemetry digest, HMAC-SHA256,
persistent freshness anchor и sealed recovery mirror. Отдельные тесты продолжают проверять
tamper, stale, replay, response/request binding, restart recovery и fail-closed при полной
потере freshness state.

Для закрытия исходного замечания КИЕ больше **не зависит от произвольного top-level поля
discovery response**. В Open5GS v2.7.6 используется существующий schema-defined контейнер
`NFProfile.customInfo`, присутствующий в модели NFProfile TS 29.510.

Build-time patch `stage39/live_open5gs/patch_nfprofile_custom_info.py` обеспечивает три
необходимых свойства живого Open5GS:

1. входящий `NFProfile.customInfo` сохраняется в состоянии NF instance внутри NRF;
2. штатный builder NFProfile возвращает сохранённый `customInfo` через NFM profile GET и
   Nnrf discovery;
3. штатный `ogs_nnrf_nfm_build_update()` живой NSSF добавляет `/customInfo` к своему
   **нативному heartbeat PATCH**, а NRF обрабатывает этот PatchItem.

В live-тесте KIE проходит цепочку:

`NSSF process → native Open5GS heartbeat PATCH → nnrf-nfm → NRF internal NF state →
individual NFM GET / nnrf-disc → verifier`.

Подтверждённый run 39114423432 получил следующие результаты:

- `schema_defined_container = NFProfile.customInfo`;
- `schema_source = 3GPP TS 29.510 NFProfile`;
- `native_open5gs_heartbeat_patch = true`;
- `nfm_profile_get_round_trip = true`;
- `discovery_round_trip = true`;
- request HMAC verified: true;
- response HMAC verified: true;
- request/response cycle+nonce binding: true;
- replay после повторного нативного heartbeat отвергнут;
- stale KIE, реально прошедшая через heartbeat/NRF/discovery, отвергнута;
- KIE с изменённым MAC, реально прошедшая тем же путём, отвергнута;
- после отрицательных случаев новый корректный cycle принят;
- проверены валидные cycles 7001 и 7004;
- очистка через heartbeat с пустым `customInfo` успешно удаляет KIE;
- legacy top-level `x-stage39-kie` отсутствует;
- после удаления сохраняется обычный backward-compatible discovery.

Старый код инъекции top-level `x-stage39-kie` удалён из
`stage39-nnrf-handler.c`; live evidence теперь формируется только через NFProfile/NFM path.

Таким образом исходный пункт «КИЕ отсутствует в реализации / не входит в исполняемый SBI path»
закрыт: KIE является реальным сообщением, которое проходит через работающий Open5GS NF,
его штатный heartbeat-механизм, Nnrf_NFManagement, состояние NRF и последующее чтение.

Научная граница формулируется уже иначе: **сам KIE payload остаётся research-defined**.
Стандартизованным является контейнер `NFProfile.customInfo`, а не семантика KIE. Поэтому
работа не заявляет появление нового 3GPP KIE IE и не требует такого заявления для
экспериментального доказательства реализации.

## 8. Live Open5GS coverage

Live workflow поднимает Open5GS v2.7.6:

- NRF;
- SCP;
- NSSF × 2;
- AUSF × 2;
- BSF × 2;
- UDM × 2;
- AMF;
- SMF;
- PCF.

Итого **13 процессов / 9 типов NF**.

NRF discovery counts совпадают с ожидаемыми. Для шести семейств статьи и четырёх вариантов:

`9 NF types × 6 families × 4 variants = 216`.

Дополнительно 9 duplicate-profile cases. Итог: **225/225 native mutations обнаружены**,
а marker count внутри нативного NRF response hook также равен 225.

## 9. Live Open5GS mTLS

Отдельный pass поднимает те же NF с TLS SBI configuration. Подтверждено:

- TLS 1.3;
- клиент без сертификата отклонён;
- authenticated Nnrf discovery успешен;
- ожидаемые discovery counts сохранены.

CI PKI упрощена: один короткоживущий сертификат с SAN для loopback endpoints используется
всеми NF. Это mTLS enforcement experiment, но не production per-NF PKI и не conformance
certification.

OAuth2 client-credentials продолжает проверяться в отдельном transport probe. Для Open5GS
v2.7.6 в данном стенде не обнаружен используемый NRF OAuth2 token-handler, поэтому этот тест
не называется native Open5GS OAuth2.

SEPP-like envelope также остаётся property test, а не N32/SEPP conformance.

## 10. Reproducibility boundaries

GitHub Actions сохраняет отдельные artifacts:

- `stage39-kie-streaming-evidence`;
- `stage39-soak-evidence`;
- `stage39-churn-evidence`;
- `stage39-live-open5gs-evidence`.

Каждый artifact получает SHA-256 digest от GitHub Actions. Frozen Stage38 artifacts не
перезаписываются.

## 11. Что остаётся открытым

После Stage39 исходные семь замечаний существенно сокращены, но не все превращены в
production-grade доказательство. Остаются:

- policy authority логически отделена от NRF, но не вынесена в отдельную организацию/HSM;
- witness sidecar и Open5GS используют один GitHub runner/kernel;
- completed PR churn сейчас 2 минуты; двухчасовой scheduled workflow реализован, но
  многочасовой результат следует заявлять только после фактического завершённого run;
- SBI load не является настоящей UE registration/PDU-session нагрузкой;
- external-controller onset является лабораторным attacker trigger, а не timestamp
  неконтролируемого удалённого нарушителя;
- KIE payload внутри schema-defined `NFProfile.customInfo` остаётся research-defined и не является новым стандартизованным 3GPP IE;
- native Open5GS OAuth2 authorization flow не подтверждён;
- N32/SEPP interoperability/conformance не выполнялся;
- нет TPM/TEE/remote-attestation измерения executable/container image;
- нет multi-vendor core validation.

Эти границы должны сохраняться в статье, чтобы Stage39 усиливал практическую и теоретическую
значимость работы без расширения выводов за фактически выполненный эксперимент.
