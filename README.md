PolySphinx Paper
================

This repository contains the artifacts of the PolySphinx evaluation. This includes:

* The implementation of PolySphinx in Rust, in the directory `polysphinx/`.
* Benchmarks of this implementation and a Sphinx implementation, in the directory `benchmarks/`.
* The adapted Rollercoaster simulator, in the directory `rollercoaster/`.
* The Jupyter notebook for the size/bandwidth overhead evaluation, as `size_evaluation.ipynb`.

The PolySphinx implementation follows standard Rust practice and can be
included via cargo. You can build the API documentation by using `cargo doc`.

The benchmarks are using `criterion`, and as such, can be run by using `cargo
bench` or `cargo criterion` in the `benchmarks/` folder. The script
`make_nice_graphs.py` is provided to generate the graps as they are in the
paper, as they are not the standard `criterion` graphs.

The Rollercoaster simulator has its own README.

The size evaluation notebook can be opened with Jupyter.
