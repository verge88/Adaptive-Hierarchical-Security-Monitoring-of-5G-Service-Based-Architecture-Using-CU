# Stage53 — масштабирование до 4000 реально работающих Open5GS NF

## Цель

Stage44/45 масштабировали профили NF логическими репликами. Stage53 заменяет это допущение реальными процессами Open5GS `open5gs-nssfd`: каждый экземпляр имеет отдельный PID, собственный runtime `nfInstanceId`, индивидуальную регистрацию в NRF и собственный SBI endpoint.

Используется Open5GS v2.7.6 с тем же native runtime-witness hook, который применялся в предыдущих live-экспериментах.

## Критерии, по которым экземпляр считается реальным live NF

Для каждого NSSF одновременно требовались:

1. живой отдельный PID;
2. native runtime witness с `nfInstanceId`;
3. уникальный UUID;
4. индивидуальный GET профиля через NRF NFM API со статусом REGISTERED;
5. совпадение UUID runtime witness и NRF;
6. доступный прямой SBI endpoint;
7. один и тот же SHA-256 исполняемого `open5gs-nssfd` во всех worker.

Bulk NRF discovery измерялся отдельно и не использовался как доказательство регистрации, поскольку при больших ответах Open5GS/HTTP2 в этих запусках сбрасывал соединение.

## Stage53A — 100 live NF на одной VM

Авторитетный run: 40716501099.

Результат:
- 100/100 live NSSF processes;
- 100 уникальных PID;
- 100 runtime witness records;
- 100 уникальных runtime UUID;
- 100/100 профилей индивидуально подтверждены NRF NFM API;
- 100/100 SBI endpoints доступны;
- witness/NRF UUID sets полностью совпали;
- все проверки: PASS.

Метрики:
- registration convergence: 12.55 s;
- median RSS/NF: 15.894 MiB;
- p95 RSS/NF: 16.262 MiB;
- max RSS/NF: 16.402 MiB;
- cgroup memory.current после hold: ~672 MB;
- 100 idle NSSF использовали 0.06 CPU-s за 20 s hold;
- binary SHA-256: `95c5cebdf3b94692fcc19740b03fa8808672ece4f88225adaf2cbabb772fc796`.

Evidence artifact:
- `stage53a-100-live-nf-evidence`;
- ID 12827618933;
- SHA-256 `47a6eb54ca6a86ee0ca93a75d13d89f1b284cc65fe55edc9d47ac710e241ee77`.

## Stage53B — 1000 одновременно live NF

Основной multi-worker run: 40718981055.

Архитектура:
- 4 GitHub-hosted runner jobs;
- 250 live NSSF на worker;
- локальный NRF + SCP на каждом worker;
- 300 s hold после полной проверки worker.

Все четыре worker завершились success. Из-за синтаксической ошибки только в исходном aggregation script финальный aggregate-job этого run упал уже после успешного получения всех четырёх worker artifacts. Поэтому результат повторно проверен отдельным audit-job без перезапуска NF.

Авторитетный audit run: 40720750770.

Результат аудита:
- workers: 4;
- live processes: 1000/1000;
- runtime witnesses: 1000/1000;
- NRF NFM verified: 1000/1000;
- direct SBI reachable: 1000/1000;
- глобально уникальные UUID: 1000/1000;
- SHA-256 Open5GS binary одинаков на всех workers;
- реальное одновременное окно всех 1000 NF: 215.074 s;
- registration convergence median: 13.625 s;
- max: 14.365 s;
- 4 unique runner names;
- 4 unique boot-id hashes;
- 2 unique hostnames и 2 unique machine-id hashes.

Последние два значения нельзя использовать как доказательство четырёх разных физических серверов: GitHub-hosted images могут повторно использовать шаблонные machine-id/hostname свойства. Наличие четырёх различных runner names и boot-id подтверждает четыре отдельных job/VM execution contexts, но не bare-metal separation.

Audit artifact:
- `stage53b-1000-live-nf-audit-evidence`;
- ID 12830781465;
- SHA-256 `a9dd794c3d1645e1ef36de117a09d1e4d41868894aefda9dca450bba2e8c91b0`.

## Stage53C — 4000 одновременно live NF

Авторитетный run: 40720929292.

Архитектура:
- 8 GitHub-hosted runner jobs;
- 500 real Open5GS NSSF processes на worker;
- локальный NRF + SCP на каждом worker;
- 900 s hold;
- aggregate запускается только после завершения всех восьми workers.

Все восемь workers и aggregate завершились success.

Итог:
- workers: 8;
- requested/live NF: 4000/4000;
- runtime witness records: 4000/4000;
- индивидуально подтверждённые NRF NFM profiles: 4000/4000;
- прямые SBI endpoints: 4000/4000;
- глобально уникальные UUID: 4000/4000;
- все worker-level checks: PASS;
- binary SHA-256 одинаков на всех восьми workers:
  `95c5cebdf3b94692fcc19740b03fa8808672ece4f88225adaf2cbabb772fc796`;
- одновременное live-окно всех 4000 NF: 745.267 s (~12 min 25 s);
- registration convergence median: 14.670 s;
- max: 15.265 s;
- суммарный `cgroup memory.current` восьми worker-контейнеров после hold: 27,488,280,576 bytes (~25.6 GiB);
- сумма per-process RSS: 63,218,356 KiB, но RSS существенно переоценивает физическую память из-за общих mapped pages;
- 8 unique runner names;
- 8 unique boot-id hashes;
- 2 unique hostnames и 2 unique machine-id hashes;
- bulk SearchResult success: 0/8 workers; индивидуальная NFM-проверка 4000/4000 успешна.

Aggregate artifact:
- `stage53c-4000-live-nf-aggregate-evidence`;
- ID 12831693039;
- SHA-256 `6cd69e7ab60cfb2ccbdfd00267b3e717b058bb479e60165abc69a99e6e0d6ec5`.

## Интерпретация

Stage53C устраняет прежнее ограничение, согласно которому масштаб 1040/4160/8320 достигался синтетическими логическими репликами NFProfile. Здесь одновременно работали 4000 отдельных процессов `open5gs-nssfd`, и каждый из них независимо подтвердил runtime UUID, NRF NFM registration и SBI reachability.

Эксперимент подтверждает горизонтальное масштабирование количества реально работающих NF процессов до 4000 при шардировании нагрузки на восемь worker execution contexts.

## Важные ограничения

1. Это не один Open5GS core и не один NRF с 4000 регистрациями. Каждый из восьми workers имел собственный локальный NRF/SCP и 500 NSSF.
2. Поэтому эксперимент доказывает 4000 одновременно live Open5GS NF и горизонтальную process-density scalability, но не single-NRF scalability до 4000.
3. Bulk NRF SearchResult оказался отдельным ограничением: большие discovery responses приводили к HTTP/2 connection reset, хотя индивидуальные NFM GET подтверждали все регистрации.
4. GitHub-hosted runner separation не является доказательством различных bare-metal hosts.
5. Все 4000 NF относятся к одному типу NSSF; heterogeneous 4000-NF deployment пока не исследован.
6. Трафик между worker-шардами отсутствовал: каждый shard использовал локальный NRF/SCP.

## Следующий эксперимент

Наиболее важное продолжение после Stage53 — вынести NRF в общий внешний endpoint и заставить несколько worker-hosts зарегистрировать NF в одном или нескольких общих NRF. Это отделит масштабирование самих NF-процессов от масштабирования NRF registry/discovery plane и позволит измерить предел single-NRF / replicated-NRF при 1000–4000 реальных регистрациях.
