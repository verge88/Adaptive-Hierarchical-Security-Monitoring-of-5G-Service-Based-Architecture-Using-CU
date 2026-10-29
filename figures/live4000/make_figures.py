#!/usr/bin/env python3
"""Publication-grade plots from Table 5 of the 4000-live-NSSF article.

These are visualizations of existing experimental measurements, not new runs.
"""
from __future__ import annotations

import argparse
import csv
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter, MultipleLocator

ROOT = Path(__file__).resolve().parent
DATA_CSV = ROOT / "table5_live4000.csv"
METHODS = ("centralized", "fixed_hierarchical", "adaptive_hierarchical")
LABELS = (
    "Централизованный",
    "Фиксированный иерархический",
    "Адаптивный иерархический",
)
COLORS = ("#436886", "#87A5B9", "#167A69")
TEXT = "#182D3D"
MUTED = "#506477"
GRID = "#E2E9EE"
BACKGROUND = "#FFFFFF"


def read_table() -> dict[str, dict[str, float]]:
    with DATA_CSV.open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream))
    assert {r["method"] for r in rows} == set(METHODS), "Unexpected method names"
    data = {
        r["method"]: {
            "deep_checks": float(r["deep_checks"]),
            "coordinator_bytes": float(r["coordinator_bytes"]),
        }
        for r in rows
    }
    # Guard against accidental changes to the published Table 5.
    assert data["centralized"]["deep_checks"] == 4000
    assert data["fixed_hierarchical"]["deep_checks"] == 4000
    assert abs(data["adaptive_hierarchical"]["deep_checks"] - 264.74) < 1e-9
    assert abs(data["centralized"]["coordinator_bytes"] - 2577839.89) < 1e-6
    assert abs(data["fixed_hierarchical"]["coordinator_bytes"] - 296362.37) < 1e-6
    assert abs(data["adaptive_hierarchical"]["coordinator_bytes"] - 296366.37) < 1e-6
    return data


def fmt_ru(value: float, digits: int = 2) -> str:
    s = f"{value:,.{digits}f}"
    return s.replace(",", " ").replace(".", ",")


def layout(title: str, subtitle: str, improvement: str):
    fig = plt.figure(figsize=(10.8, 5.0), facecolor=BACKGROUND)
    ax = fig.add_axes([0.355, 0.245, 0.575, 0.555])
    fig.text(0.045, 0.93, title, fontsize=18, fontweight="bold",
             color=TEXT, ha="left", va="top")
    fig.text(0.045, 0.855, subtitle, fontsize=10.7,
             color=MUTED, ha="left", va="top")
    fig.text(0.935, 0.927, improvement, fontsize=15.3, fontweight="bold",
             color=COLORS[2], ha="right", va="top")
    ax.set_facecolor(BACKGROUND)
    ax.set_axisbelow(True)
    ax.grid(axis="x", color=GRID, linewidth=0.9)
    ax.set_yticks([2, 1, 0], LABELS, fontsize=11)
    ax.tick_params(axis="y", length=0, pad=12, colors=TEXT)
    ax.tick_params(axis="x", labelsize=10, length=0, colors=MUTED, pad=7)
    for edge in ("top", "right", "left"):
        ax.spines[edge].set_visible(False)
    ax.spines["bottom"].set_color("#A9BCC8")
    ax.spines["bottom"].set_linewidth(0.9)
    ax.set_ylim(-0.55, 2.55)
    return fig, ax


def save(fig, dest: Path, stem: str):
    dest.mkdir(parents=True, exist_ok=True)
    for extension in ("png", "svg"):
        path = dest / f"{stem}.{extension}"
        fig.savefig(path, dpi=320, facecolor=BACKGROUND,
                    bbox_inches="tight", pad_inches=0.2)
        print(path, f"({path.stat().st_size} bytes)")
    plt.close(fig)


def plot_deep_checks(data: dict, dest: Path) -> None:
    base = data["centralized"]["deep_checks"]
    adaptive = data["adaptive_hierarchical"]["deep_checks"]
    gain = (1 - adaptive / base) * 100
    fig, ax = layout(
        "Количество углублённых проверок",
        "Средние значения по 27 детерминированным испытаниям · 4000 NSSF",
        f"−{fmt_ru(gain)} %",
    )
    vals = [data[m]["deep_checks"] for m in METHODS]
    bars = ax.barh([2, 1, 0], vals, height=0.53,
                   color=COLORS, edgecolor="none")
    for bar, value in zip(bars, vals):
        digits = 2 if value % 1 else 0
        ax.text(value + 75, bar.get_y() + bar.get_height() / 2,
                fmt_ru(value, digits), ha="left", va="center",
                color=TEXT, fontsize=11, fontweight="bold")
    ax.set_xlim(0, 4900)
    ax.xaxis.set_major_locator(MultipleLocator(1000))
    ax.xaxis.set_major_formatter(FuncFormatter(
        lambda x, pos: f"{x:,.0f}".replace(",", " ")
    ))
    ax.set_xlabel("Углублённые проверки на цикл, ед.", fontsize=11,
                  color=MUTED, labelpad=12)
    fig.text(0.045, 0.085,
             "Примечание. Все 4000 профилей проходили предварительную проверку.",
             fontsize=10.3, color=MUTED, ha="left")
    fig.text(0.045, 0.045,
             "Экономия относится только к углублённым операциям, а не ко времени выполнения.",
             fontsize=10.3, color=MUTED, ha="left")
    save(fig, dest, "fig_01_deep_checks")


def plot_bytes(data: dict, dest: Path) -> None:
    base = data["centralized"]["coordinator_bytes"]
    adaptive = data["adaptive_hierarchical"]["coordinator_bytes"]
    gain = (1 - adaptive / base) * 100
    fig, ax = layout(
        "Данные, передаваемые координатору",
        "Средние значения по 27 испытаниям · объём сериализованных сведений",
        f"−{fmt_ru(gain)} %",
    )
    vals = [data[m]["coordinator_bytes"] for m in METHODS]
    bars = ax.barh([2, 1, 0], [x / 1_000_000 for x in vals],
                   height=0.53, color=COLORS, edgecolor="none")
    for bar, value in zip(bars, vals):
        x = value / 1_000_000
        ax.text(x + 0.045, bar.get_y() + bar.get_height() / 2,
                f"{fmt_ru(value)} байт", ha="left", va="center",
                color=TEXT, fontsize=10.2, fontweight="bold")
    ax.set_xlim(0, 3.32)
    ax.xaxis.set_major_locator(MultipleLocator(0.5))
    ax.xaxis.set_major_formatter(FuncFormatter(
        lambda x, pos: f"{x:.1f}".replace(".", ",")
    ))
    ax.set_xlabel("Сериализованные данные, МБ (10⁶ байт)", fontsize=11,
                  color=MUTED, labelpad=12)
    fig.text(0.045, 0.085,
             "Примечание. Измерен размер данных на входе координатора.",
             fontsize=10.3, color=MUTED, ha="left")
    fig.text(0.045, 0.045,
             "Полный сетевой трафик, процессорное время и задержка обнаружения не измерялись.",
             fontsize=10.3, color=MUTED, ha="left")
    save(fig, dest, "fig_02_coordinator_data")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, default=ROOT / "out")
    args = parser.parse_args()
    plt.rcParams.update({
        "font.family": "DejaVu Sans",
        "font.size": 11,
        "svg.fonttype": "none",     # editable real SVG text
        "axes.unicode_minus": False,
        "savefig.facecolor": BACKGROUND,
        "figure.facecolor": BACKGROUND,
    })
    data = read_table()
    plot_deep_checks(data, args.output_dir)
    plot_bytes(data, args.output_dir)


if __name__ == "__main__":
    main()
