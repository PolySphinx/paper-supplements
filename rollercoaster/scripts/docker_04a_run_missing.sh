#!/bin/bash
docker run -v "$(pwd)/pickles":/rollercoaster/pickles:z -it rollercoaster-pypy sh -c "python3 scripts/list_missing_outputs.py pickles | grep MISSING | cut -d ' ' -f 2 | awk 'gsub(\".output\", \"\")' | xargs python3 parallelrunner.py";
