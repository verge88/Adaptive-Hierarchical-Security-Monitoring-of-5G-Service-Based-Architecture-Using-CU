# Stage51 — независимые корни доказательств идентичности NF

## Цель

Stage49 показал принципиальную слабость: согласованная подмена `nfInstanceId` одновременно в NFProfile и witness проходит базовую проверку, поскольку оба источника подтверждают одну и ту же ложную идентичность. Stage51 проверяет усиленную архитектуру с тремя независимыми failure domains.

## Корни доверия

1. **Root A — NFProfile + witness.** Эти два источника намеренно рассматриваются как один common-mode failure domain.
2. **Root B — lifecycle authorization anchor.** Отдельный GitHub Actions job генерирует эфемерный ключ Ed25519 и подписывает manifest, связывающий slot, endpoint, NF type, policy version и разрешённый `nfInstanceId`.
3. **Root C — внешний runtime identity oracle.** Отдельный pinned Render instance во Frankfurt отвечает на challenge-bound запросы и возвращает runtime identity, привязанную к slot/trial и hash неизменяемой identity map.

Решение принимается только если все три корня связываются с одним и тем же `nfInstanceId`; любое расхождение приводит к fail-closed.

## Эксперимент

Использованы только 12 профилей, реально полученных через HTTP/2 discovery в Stage42. Policy-constructed NRF исключён. Выполнено 8 trials для каждого live NF, всего 96 identity-cases.

Для каждого случая проверены:
- штатное состояние;
- компрометация Profile+Witness;
- Profile+Witness + lifecycle anchor;
- Profile+Witness + runtime oracle;
- только lifecycle anchor;
- только runtime oracle;
- lifecycle anchor + runtime oracle;
- согласованная компрометация всех трёх корней;
- replay ранее принятого runtime response;
- повреждение подписанного lifecycle manifest.

## Подтверждённые результаты

- 96/96 штатных состояний приняты.
- Базовый Stage44 пропустил 96/96 согласованных подмен Profile+Witness.
- Усиленная Stage51-схема обнаружила:
  - Profile+Witness: 96/96;
  - Profile+Witness + lifecycle: 96/96;
  - Profile+Witness + runtime: 96/96;
  - lifecycle only: 96/96;
  - runtime only: 96/96;
  - lifecycle + runtime: 96/96.
- Итого: 576/576 одиночных и двойных компрометаций корней обнаружены.
- 96/96 replay runtime responses отклонены по challenge binding.
- Повреждённый lifecycle manifest отклонён по Ed25519 signature verification.
- При согласованной компрометации всех трёх корней 96/96 ложных состояний были приняты. Это намеренно подтверждённая граница модели доверия.

## Воспроизводимость

- GitHub Actions run: 40699571702.
- Stage51 evidence artifact: 12820284561.
- Artifact ZIP SHA-256: 2b45e5674d6a2a4f481132eca08c70ce6a245afad2dbc38b9d1dc545e821a2ea.
- Lifecycle-anchor artifact: 12821835014.
- Lifecycle artifact ZIP SHA-256: 9178c6036d3e24a3773fc448a5900b993759b0f0761f75972783f6dd35a60c4e.
- Lifecycle Ed25519 public-key SHA-256: bd7ad1c027edcfcc6e631b25e16d67bd5c56ac09df764468a6c8a146bf597e49.
- Render identity-map SHA-256: d0aece53c9f7b22798bfe1590d6abc8ad7380b3d0b589483d51dc330ef92cb0f.
- Render experiment commit: 09eca24d6c8fa7ba075cf8c439dd98c9c3eb4c01.
- Render experiment instance: srv-dbguppnb9u1s7399r4p0-hibernate-55854dcfc9-7rvkb.

## Ограничения

- Runtime oracle выполнялся на независимом Render instance, но не являлся самим исходным Open5GS NF и не имел TEE/TPM attestation.
- Lifecycle private key был эфемерным ключом отдельного GitHub Actions job, а не HSM-backed production key.
- Использованы сохранённые 12 live Stage42 discovery-профилей; новые регистрации Open5GS в Stage51 не создавались.
- Если Profile/Witness, lifecycle authority и runtime identity root одновременно скомпрометированы согласованно, схема не может отличить ложное состояние от истинного.

## Вывод

Stage51 экспериментально переводит обнаруженный в Stage49 common-mode failure из двухисточниковой схемы в явно сформулированную трёхкорневую модель доверия. При сохранении хотя бы одного честного независимого корня все исследованные одиночные и двойные компрометации обнаружены. Полная согласованная компрометация всех трёх корней остаётся фундаментальной границей и должна рассматриваться как отдельный out-of-scope trust assumption либо закрываться аппаратной/облачной аттестацией и дополнительным независимым источником.
