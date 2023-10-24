#!/bin/zsh

. bin/activate.sh
curl -s https://easylist.to/easylist/easylist.txt
ab2cb -o rules.json easylist.txt
