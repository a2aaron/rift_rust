#!/usr/bin/env fish

cargo run -- --topology topology/two_by_two_by_two_ztp.yaml --snapshot 0.1 --max-snapshots 30 --max-level debug
for FILE in logs/*.json
    set BASENAME (basename $FILE .json)
    python3 graph.py $FILE logs/$BASENAME.dot
    dot logs/$BASENAME.dot -Tpng > logs/$BASENAME.png
end
