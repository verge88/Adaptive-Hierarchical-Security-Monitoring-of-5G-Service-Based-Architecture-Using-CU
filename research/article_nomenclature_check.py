"""Publication nomenclature guard for the Russian article.

The scientific narrative must not use internal Stage 15..21 labels.
Those labels are allowed only in the reproducibility section where the
publication experiment names are mapped to repository artifacts.
"""
from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ARTICLE = ROOT / "article" / "EXPERIMENTAL_PROGRAM_RU.md"
MARKER = "## 5. Правило использования внутренних названий Stage"
PATTERN = re.compile(
    r"Stage\s*-?\s*(?:15|16|17|18|19|20|21)",
    re.IGNORECASE,
)


def main():
    text = ARTICLE.read_text(encoding="utf8")
    marker = text.find(MARKER)
    if marker < 0:
        raise AssertionError(
            "Reproducibility marker missing from publication program"
        )

    scientific_body = text[:marker]
    matches = list(PATTERN.finditer(scientific_body))
    if matches:
        details = ", ".join(
            f"{m.group(0)!r}@{m.start()}"
            for m in matches
        )
        raise AssertionError(
            "Internal Stage labels leaked into scientific narrative: "
            + details
        )

    required_titles = (
        "Эксперимент 1. Внутрисемейная проверка",
        "Эксперимент 2. Проверка при сдвиге распределения",
        "Эксперимент 3. Направленное последовательное",
        "Эксперимент 4. Слепая проверка переносимости",
        "Эксперимент 5. Память разреженных событий",
        "Эксперимент 6. Структурная сверка",
        "Эксперимент 7. Семантическая сверка",
        "Масштабная независимая репликация",
        "Единое абляционное исследование",
        "Анализ времени до обнаружения",
        "Оценка накладных расходов",
        "Формальная модель доверия и нарушителя",
    )
    missing = [
        title for title in required_titles
        if title not in scientific_body
    ]
    if missing:
        raise AssertionError(
            "Publication experiment structure incomplete: "
            + "; ".join(missing)
        )

    print(
        "ARTICLE_NOMENCLATURE_OK "
        "internal Stage labels confined to reproducibility section"
    )


if __name__ == "__main__":
    main()
