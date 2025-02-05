#!/bin/bash
# Copyright (c) 2017 pandas-gbq Authors All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

set -e -x
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )"

# Install dependencies using Conda

conda config --set always_yes yes --set changeps1 no
conda config --add channels pandas
conda config --add channels conda-forge
conda update -q conda
conda info -a
conda create -q -n test-environment python=$PYTHON
source activate test-environment
REQ="ci/requirements-${PYTHON}-${PANDAS}"
conda install -q --file "$REQ.conda";

if [[ "$PANDAS" == "NIGHTLY" ]]; then
  conda install -q numpy pytz python-dateutil;
  PRE_WHEELS="https://7933911d6844c6c53a7d-47bd50c35cd79bd838daf386af554a83.ssl.cf2.rackcdn.com";
  pip install --pre --upgrade --timeout=60 -f $PRE_WHEELS pandas;
else
  conda install -q pandas=$PANDAS;
fi

python setup.py develop --no-deps

# Run the tests
$DIR/run_tests.sh
