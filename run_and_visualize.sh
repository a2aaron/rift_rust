#!/usr/bin/env fish

cargo run -- --topology topology/two_by_two_by_two_ztp.yaml --snapshot 3 --max-snapshots 3 --max-level debug
for FILE in logs/*.json
    set BASENAME (basename $FILE .json)
    python3 graph.py $FILE logs/$BASENAME.dot
    dot logs/$BASENAME.dot -Tpng > logs/$BASENAME.png
end
