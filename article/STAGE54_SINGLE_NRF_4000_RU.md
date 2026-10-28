# Stage54 — 4000 реальных Open5GS NF за одним NRF

## Цель

Stage53 подтвердил 4000 одновременно работающих Open5GS NSSF при горизонтальном шардировании по восьми worker execution contexts, но каждый shard имел собственный NRF. Stage54 проверяет более сильное условие: один процесс Open5GS NRF v2.7.6 должен одновременно обслужить тысячи реально работающих NSSF с индивидуальной runtime-идентичностью и SBI endpoint.

## Критерии подтверждения

Для каждого NSSF требовались:
1. отдельный живой PID;
2. native runtime witness с nfInstanceId;
3. уникальный runtime UUID;
4. индивидуальный GET профиля через один NRF NFM API со статусом REGISTERED;
5. точное совпадение witness UUID и NRF UUID;
6. доступный прямой SBI endpoint;
7. NRF должен оставаться жив в момент измерения.

Bulk NRF discovery SearchResult измерялся отдельно и не использовался как критерий регистрации.

## Успешная шкала одного NRF

На одной GitHub-hosted runner VM с одним Open5GS NRF успешно подтверждены:
- 1000 live NSSF — convergence 17.378 s;
- 1500 — 19.578 s;
- 2000 — 30.674 s;
- 2500 — 30.392 s;
- 3000 — 77.509 s;
- 3500 — 260.402 s;
- 4000 — успешно после увеличения SBI/peer capacity.

Рост между 3000 и 3500 является выраженно нелинейным, поэтому 3500 не интерпретируется как жесткий предел NRF.

## Авторитетный Stage54E — 4000 NSSF, один NRF + SCP

Run: 40738466509.

Конфигурация:
- один Open5GS NRF v2.7.6;
- один SCP;
- 4000 отдельных процессов open5gs-nssfd;
- peer/SBI capacity поднята до 8192;
- 8 GiB дополнительного swap для устранения host-memory ambiguity.

Результат:
- requested/live: 4000/4000;
- runtime witnesses: 4000;
- unique witness UUID: 4000;
- NRF NFM verified: 4000/4000;
- unique NFM UUID: 4000;
- direct SBI reachable: 4000/4000;
- NRF жив в момент измерения;
- all checks: PASS;
- registration convergence: 158.378 s;
- cgroup memory.current after hold: 15,319,830,528 bytes;
- bulk SearchResult: FAIL, ConnectionResetError [Errno 104].

Evidence artifact:
- stage54e-single-nrf-4000-tuned-pools-evidence;
- ID 12839755007;
- SHA-256 910be6e3a0efda7f5454fe827d23c293db0bed2a0a00f089004ad15fabe39d8c.

## Контроль Stage54F — 4000 NSSF, один NRF без SCP

Run: 40738386859.

SCP полностью исключен, чтобы отделить NRF registry scale от NRF→SCP status-notification fanout.

Результат:
- 4000/4000 live NSSF;
- 4000 unique runtime UUID;
- 4000/4000 NRF NFM verified;
- 4000/4000 SBI reachable;
- all checks: PASS;
- registration convergence: 210.562 s;
- cgroup memory.current after hold: 15,469,051,904 bytes;
- bulk SearchResult: FAIL с тем же ConnectionResetError.

Evidence artifact:
- stage54f-single-nrf-4000-no-scp-evidence;
- ID 12839680300;
- SHA-256 22beb2d374f460f0edce9fb019813e2bd03064c321286a4cf1cf80ba6433af54.

## Интерпретация

Stage54 устраняет ограничение Stage53, связанное с несколькими NRF domains: один Open5GS NRF v2.7.6 действительно удерживал и индивидуально возвращал 4000 одновременно зарегистрированных реальных NSSF.

Предыдущий отказ 4000 при меньших pool limits не является доказательством фундаментального предела NRF. После увеличения capacity 4000/4000 прошли полный набор process/runtime/NFM/SBI checks.

Одновременно обнаружено отдельное ограничение discovery plane: полный bulk SearchResult для больших наборов профилей сбрасывает HTTP/2 соединение даже тогда, когда все записи по отдельности доступны через NFM.

## Ограничения

1. Все 4000 NF — одного типа NSSF.
2. NRF и NSSF находятся на одной managed runner VM; это не cross-site deployment.
3. Наличие 8 GiB дополнительного swap устраняет часть риска OOM, но не моделирует production sizing.
4. Bulk discovery на 4000 не подтвержден.
5. Нет измерения устойчивости при churn/restart 4000 NF за одним NRF.
6. Это Open5GS v2.7.6; результат не переносится автоматически на другие NRF implementations.

## Следующий эксперимент

Следующий этап должен изолировать причину bulk-discovery failure: HTTP/2 flow-control/response buffering, server-side SearchResult construction, client close/reset behavior либо необходимость bounded/paginated discovery. Цель — получить корректный полный или стандартизированно сегментированный discovery результат для всех 4000 зарегистрированных NF.
