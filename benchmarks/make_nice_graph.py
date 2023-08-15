#!/usr/bin/python3
"""Extract Criterion benchmark data and make a nice plot.

The default graph made by Criterion is colour coded and therefore bad for B/W
printouts or colourblind people. Criterion itself doesn't offer a lot of
customization, even though the gnuplot backend is very configurable.

This script extracts the benchmark data and uses a custom gnuplot script to
generate a "better" graph.
"""
import os
import re
import sys
import json
import shutil
import tempfile
import argparse
import subprocess

from typing import NamedTuple
from pathlib import Path


UNIT_SCALE = 1000
UNIT_NAME = "us"


class Measurement(NamedTuple):
    value: int
    mean: float
    mean_lower: float
    mean_upper: float


class BenchResult(NamedTuple):
    function_id: str
    group_id: str
    values: list[Measurement]


def main():
    criterion_path = Path("target") / "criterion"
    graph_unwrap_header(criterion_path / "unwrap_header", Path("unwrap_header.svg"))
    # Skip the "create header" graph, as that doesn't really tell us much and
    # only takes up space in the paper:
    # graph_create_header(criterion_path / "create_header", Path("create_header.svg"))


def graph_create_header(bench_folder, output_path):
    cwd = Path.cwd()
    groups = []
    for folder in bench_folder.iterdir():
        if folder.name == "report":
            continue

        main_benchmark = folder / "base" / "benchmark.json"

        with open(main_benchmark, "rb") as json_file:
            data = json.load(json_file)

        function_id = data["function_id"]

        value_file = folder / "base" / "estimates.json"
        with open(value_file, "rb") as json_file:
            data = json.load(json_file)

        mean = data["mean"]["point_estimate"] / UNIT_SCALE
        mean_lower = (
            data["mean"]["confidence_interval"]["lower_bound"] / UNIT_SCALE
        )
        mean_upper = (
            data["mean"]["confidence_interval"]["upper_bound"] / UNIT_SCALE
        )

        groups.append((function_id, Measurement(None, mean, mean_lower, mean_upper)))

    with tempfile.TemporaryDirectory() as tempdir:
        with open(Path(tempdir) / "benchmark.dat", "w") as datafile:
            for (i, (name, measurement)) in enumerate(groups):
                datafile.write(f"{i} {name!r} {measurement.mean} {measurement.mean_lower} {measurement.mean_upper}\n\n")

        with open(Path(tempdir) / "plot.gnu", "w") as scriptfile:
            scriptfile.write("set terminal svg size 500,500 dynamic linewidth 1.5\n")
            scriptfile.write('set output "output.svg"\n')
            scriptfile.write('set title noenhanced "create_header: comparison"\n')
            scriptfile.write(f'set ylabel "Average Time ({UNIT_NAME})"\n')
            scriptfile.write("set grid ytics\n")
            scriptfile.write("set style fill pattern 1\n")
            scriptfile.write("set boxwidth 0.5\n")
            scriptfile.write("set key off\n")
            scriptfile.write('plot [-0.5:1.5] [0:] "benchmark.dat" using 1:3:xtic(2) with boxes\n')

        os.chdir(tempdir)
        subprocess.run(["gnuplot", "plot.gnu"])
        os.chdir(cwd)
        shutil.copyfile(Path(tempdir) / "output.svg", output_path)


def graph_unwrap_header(bench_folder, output_path):
    cwd = Path.cwd()

    bench_groups = []
    for bench_group_path in bench_folder.iterdir():
        if re.match("\\d+", bench_group_path.name) or bench_group_path.name == "report":
            continue
        bench_groups.append(read_bench(bench_group_path))

    bench_groups.sort()
    title = bench_groups[0].group_id

    with tempfile.TemporaryDirectory() as tempdir:
        export_data(bench_groups, Path(tempdir) / "benchmark.dat")
        export_script("", bench_groups, Path(tempdir) / "plot.gnu")

        os.chdir(tempdir)
        subprocess.run(["gnuplot", "plot.gnu"])
        os.chdir(cwd)

        shutil.copyfile(Path(tempdir) / "output.svg", output_path)


def read_bench(path: Path) -> BenchResult:
    function_id = ""
    group_id = ""
    values: list[Measurement] = []

    for item in path.iterdir():
        main_benchmark = item / "base" / "benchmark.json"

        if not main_benchmark.is_file():
            continue

        with open(main_benchmark, "rb") as json_file:
            data = json.load(json_file)

        group_id = data["group_id"]
        function_id = data["function_id"]
        value = int(data["value_str"])

        record_path = item / "base" / "estimates.json"

        with open(record_path, "rb") as json_file:
            data = json.load(json_file)

        mean = data["mean"]["point_estimate"] / UNIT_SCALE
        mean_lower = (
            data["mean"]["confidence_interval"]["lower_bound"] / UNIT_SCALE
        )
        mean_upper = (
            data["mean"]["confidence_interval"]["upper_bound"] / UNIT_SCALE
        )

        values.append(Measurement(value, mean, mean_lower, mean_upper))

    values.sort()
    return BenchResult(function_id, group_id, values)


def export_data(bench_groups: list[BenchResult], path: Path):
    with open(path, "w") as outfile:
        for group in bench_groups:
            for measurement in group.values:
                outfile.write(
                    f"{measurement.value} {measurement.mean} {measurement.mean_lower} {measurement.mean_upper}\n"
                )
            outfile.write("\n\n")


def export_script(title: str, bench_groups: list[BenchResult], path: Path):
    with open(path, "w") as scriptfile:
        scriptfile.write("set terminal svg size 450,250 dynamic linewidth 1.5\n")
        scriptfile.write('set output "output.svg"\n')
        scriptfile.write("set key inside left reverse spacing 0.75 width -4\n")
        if title:
            scriptfile.write(f'set title noenhanced "{title}"\n')
        scriptfile.write('set xlabel "Input Size (Bytes)"\n')
        scriptfile.write(f'set ylabel "Average Time ({UNIT_NAME})"\n')
        scriptfile.write("set grid ytics\n")
        plottings = []
        for i, group in enumerate(bench_groups):
            command = f'"benchmark.dat" index {i} using 1:2 with linespoints ls {i+1} dashtype {i+1} title "{group.function_id}"'
            plottings.append(command)
        scriptfile.write("plot ")
        scriptfile.write(", ".join(plottings))
        scriptfile.write("\n")


if __name__ == "__main__":
    main()
