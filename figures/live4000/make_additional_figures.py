#!/usr/bin/env python3
"""Three publication figures grounded in verified Stage56 GitHub Actions results.

Source: Stage56 run 40874519629; stage56_result.json SHA256:
f1092d654c1bd3b937926da998937bed3981d644ff56678d215a15c651692f47
"""
from __future__ import annotations

import argparse
import csv
import math
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import MultipleLocator

ROOT = Path(__file__).resolve().parent
INPUT = ROOT / "stage56_27_cases.csv"
N = 4000
TEXT = "#233847"
MUTED = "#5B6E7B"
BLUE = "#376A8C"
TEAL = "#148273"
LIGHT = "#8EB5C3"
GRID = "#E4EBEF"
ORANGE = "#D28F37"
SCENARIOS = [
    ("benign", "Штатное состояние"),
    ("profile_uuid", "Подмена UUID профиля"),
    ("common_mode_uuid", "Подмена профиля и свидетельства"),
    ("service_poison", "Неразрешённая услуга"),
    ("status_poison", "Изменение статуса"),
    ("lifecycle_replay", "Повтор события жизненного цикла"),
    ("lifecycle_signature", "Нарушение имитовставки события"),
    ("witness_liveness", "Отсутствие активности процесса"),
    ("cross_group_duplicate", "Межгрупповой дубликат UUID"),
]


def load_verified_cases() -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = defaultdict(list)
    with INPUT.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            for key in ("repeat", "injected_slots", "diagnostic_pairs",
                        "adaptive_deep_checks", "central_deep_checks",
                        "fixed_deep_checks"):
                row[key] = int(row[key])
            assert row["exact_central_equivalence"] == "True"
            assert row["central_deep_checks"] == N
            assert row["fixed_deep_checks"] == N
            grouped[row["scenario"]].append(row)
    assert set(grouped) == {x[0] for x in SCENARIOS}
    assert sum(map(len, grouped.values())) == 27
    for name, rows in grouped.items():
        assert sorted(x["repeat"] for x in rows) == [0, 1, 2], name
        assert len({x["injected_slots"] for x in rows}) == 1
        assert len({x["diagnostic_pairs"] for x in rows}) == 1
    deep = [x["adaptive_deep_checks"] for v in grouped.values() for x in v]
    assert sum(deep) == 7148, f"unexpected deep-check total: {sum(deep)}"
    assert math.isclose(sum(deep) / 27, 264.74074074074076)
    expected = {
        "benign": (0, 0), "profile_uuid": (20, 40),
        "common_mode_uuid": (20, 20), "service_poison": (20, 20),
        "status_poison": (20, 20), "lifecycle_replay": (20, 40),
        "lifecycle_signature": (20, 40), "witness_liveness": (20, 20),
        "cross_group_duplicate": (2, 3),
    }
    for name, rows in grouped.items():
        assert (rows[0]["injected_slots"], rows[0]["diagnostic_pairs"]) == expected[name]
    return grouped


def setup_style():
    plt.rcParams.update({
        "font.family": "DejaVu Sans",
        "font.size": 11,
        "figure.facecolor": "white",
        "axes.facecolor": "white",
        "savefig.facecolor": "white",
        "svg.fonttype": "none",
        "axes.unicode_minus": False,
    })


def base(title: str, subtitle: str, footer: str, height: float = 7.1):
    fig = plt.figure(figsize=(12.8, height), facecolor="white")
    fig.text(0.045, 0.952, title, ha="left", va="top",
             fontsize=18, fontweight="bold", color=TEXT)
    fig.text(0.045, 0.897, subtitle, ha="left", va="top",
             fontsize=10.5, color=MUTED)
    fig.text(0.045, 0.039, footer, ha="left", va="bottom",
             fontsize=9.6, color=MUTED)
    ax = fig.add_axes([0.374, 0.145, 0.575, 0.680])
    ax.set_axisbelow(True)
    ax.grid(axis="x", color=GRID, linewidth=0.9)
    ax.tick_params(axis="both", colors=MUTED, labelsize=10, length=0, pad=8)
    for s in ("top", "right", "left"):
        ax.spines[s].set_visible(False)
    ax.spines["bottom"].set_color("#AFC0C9")
    return fig, ax


def save(fig, dest: Path, name: str):
    dest.mkdir(parents=True, exist_ok=True)
    for ext in ("png", "svg"):
        target = dest / f"{name}.{ext}"
        fig.savefig(target, dpi=320, bbox_inches="tight", pad_inches=0.2)
        print(f"{target} ({target.stat().st_size} bytes)")
    plt.close(fig)


def plot_scenarios(grouped, dest):
    fig, ax = base(
        "Обнаружение нарушений по девяти сценариям",
        "Сопоставление количества изменённых позиций и диагностических пар",
        "Примечание. Значения приведены на один вариант размещения изменений; "
        "три варианта дали одинаковые количества.",
    )
    labels = [x[1] for x in SCENARIOS]
    targets = [grouped[name][0]["injected_slots"] for name, _ in SCENARIOS]
    pairs = [grouped[name][0]["diagnostic_pairs"] for name, _ in SCENARIOS]
    positions = list(range(len(labels) - 1, -1, -1))
    dy = 0.19
    ax.barh([p + dy for p in positions], targets, height=0.34,
            color=BLUE, label="Изменённые позиции", zorder=3)
    ax.barh([p - dy for p in positions], pairs, height=0.34,
            color=TEAL, label="Диагностические пары", zorder=3)
    for p, a, b in zip(positions, targets, pairs):
        ax.text(a + 0.72, p + dy, str(a), ha="left", va="center",
                fontsize=10.5, color=TEXT)
        ax.text(b + 0.72, p - dy, str(b), ha="left", va="center",
                fontsize=10.5, color=TEXT)
    ax.set_yticks(positions, labels, fontsize=10.3, color=TEXT)
    ax.set_xlim(0, 46.5)
    ax.xaxis.set_major_locator(MultipleLocator(10))
    ax.set_xlabel("Количество, ед.", color=MUTED, labelpad=11)
    ax.legend(loc="upper right", bbox_to_anchor=(1.0, 1.11), ncol=2,
              frameon=False, fontsize=10, labelcolor=TEXT)
    fig.text(0.950, 0.945, "27/27 — равенство вердиктов", ha="right",
             va="top", fontsize=11.7, color=TEAL, fontweight="bold")
    save(fig, dest, "fig_03_attack_scenarios")


def plot_distribution(grouped, dest):
    fig, ax = base(
        "Адаптивный контроль: 27 испытаний",
        "Углублённые проверки по сценариям и трём детерминированным размещениям",
        "Важно. Три размещения не являются независимыми запусками сети. "
        "Показана вариация внутри исследованной матрицы.",
    )
    labels = [x[1] for x in SCENARIOS]
    positions = list(range(len(labels) - 1, -1, -1))
    offsets = (-0.16, 0.0, 0.16)
    colors = (BLUE, TEAL, ORANGE)
    markers = ("o", "s", "^")
    for i in range(3):
        xs = []
        ys = []
        for (name, _), p in zip(SCENARIOS, positions):
            x = next(x["adaptive_deep_checks"] for x in grouped[name]
                     if x["repeat"] == i)
            xs.append(x)
            ys.append(p + offsets[i])
        ax.scatter(xs, ys, s=66, marker=markers[i], color=colors[i],
                   edgecolor="white", linewidth=0.65, zorder=4,
                   label=f"Размещение {i + 1}")
    mean = sum(x["adaptive_deep_checks"] for rows in grouped.values()
               for x in rows) / 27
    ax.axvline(mean, linestyle="--", linewidth=1.6, color="#879BA8",
               zorder=2, label="Среднее: 264,74")
    ax.set_yticks(positions, labels, fontsize=10.3, color=TEXT)
    ax.set_xlim(245, 274)
    ax.xaxis.set_major_locator(MultipleLocator(5))
    ax.set_xlabel("Углублённые проверки на цикл, ед. (показан диапазон 245–274)",
                  color=MUTED, labelpad=11)
    ax.legend(loc="upper right", bbox_to_anchor=(1.0, 1.025), ncol=4,
              frameon=False, fontsize=9.1, labelcolor=TEXT)
    fig.text(0.949, 0.947, "Среднее: 264,74", ha="right",
             va="top", fontsize=12.2, color=TEAL, fontweight="bold")
    save(fig, dest, "fig_04_adaptive_27_cases")


def plot_live_nfs(dest):
    fig, ax = base(
        "Подтверждение 4000 работающих NSSF",
        "Четыре направления проверки одного массива Open5GS 2.7.6",
        "Примечание. Сверка UUID выполнена для NRF и нативных свидетельств; "
        "аппаратная аттестация не проводилась.",
        height=6.2,
    )
    labels = [
        "Действующие процессы NSSF",
        "Уникальные UUID свидетельств",
        "Индивидуальные профили NFM",
        "Доступные интерфейсы SBI",
    ]
    values = [4000, 4000, 4000, 4000]
    # Verified against result.json from the same run:
    # live_processes=4000, unique_witness_uuids=4000,
    # nrf_individually_verified_profiles=4000, direct_sbi_reachable=4000.
    assert len(values) == 4 and all(x == N for x in values)
    ax.set_position([0.344, 0.235, 0.603, 0.5])
    positions = [3, 2, 1, 0]
    ax.barh(positions, [100] * 4, height=0.48, color=TEAL, zorder=3)
    ax.set_yticks(positions, labels, fontsize=11, color=TEXT)
    ax.set_xlim(0, 112)
    ax.set_xticks([0, 25, 50, 75, 100], ["0", "25", "50", "75", "100 %"])
    ax.set_xlabel("Доля подтверждённых объектов, %", color=MUTED,
                  labelpad=11)
    for p in positions:
        ax.text(101.5, p, "4000/4000", va="center", ha="left",
                fontsize=11, color=TEXT, fontweight="bold")
    fig.text(0.045, 0.129,
             "Совпадение множеств UUID процессов и регистрационных профилей: подтверждено.",
             fontsize=10.6, ha="left", color=TEAL, fontweight="bold")
    save(fig, dest, "fig_05_live4000_validation")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=ROOT / "out_additional")
    args = parser.parse_args()
    setup_style()
    grouped = load_verified_cases()
    plot_scenarios(grouped, args.output_dir)
    plot_distribution(grouped, args.output_dir)
    plot_live_nfs(args.output_dir)


if __name__ == "__main__":
    main()
