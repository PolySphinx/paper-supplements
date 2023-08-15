#!/bin/bash
docker run -v "$(pwd)/pickles":/rollercoaster/pickles:z -v "$(pwd)/output":/rollercoaster/output:z -p 8888:8888 -it rollercoaster sh -c "jupyter notebook --ip=0.0.0.0 --allow-root";
