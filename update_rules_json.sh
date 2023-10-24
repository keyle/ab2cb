#!/bin/zsh
python3 -m venv venv
source ./venv/bin/activate
. bin/activate.sh
make dev
pip install .
wget https://easylist.to/easylist/easylist.txt
ab2cb -o rules.json easylist.txt
rm easylist.txt
