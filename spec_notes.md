# Spec Confusions

## LIE Exchange
- The FSM diagram for LIE exchange is really confusing to read. A version where the labels are closer to the arrows and the arrows do not overlap each other would be nice
    - A simplified FSM diagram showing just the "happy path" would be useful for this as well
- **The list of "action"s in the LIE exchange should really be a table, not freeform prose.**
- Additionally, the table should group similar events together. For example, HALChanged, HALSChanged, and HATChanged should all be next to each other.
- When defining `PROCESS_LIE`, step #3 has oddly inconsistent wording:
```
3. if LIE has undefined level OR  this node's level is undefined OR this node is a leaf and remote level is lower than HAT OR (LIE's level is not leaf AND its difference is more than one from this node's level) then CLEANUP, PUSH UpdateZTPOffer, PUSH UnacceptableHeader 
```

Why is "this node is a leaf and remote level is lower than HAT" in parenthesis but not "(LIE's level is not leaf AND its difference is more than one from this node's level)"? Why is "and" not capitalized in the first clause but is capitalized in the second clause? It seems to suggest a difference which does not actually appear to be there.

- When defining `PROCESS_LIE`, the following wording is given:

```
4. PUSH UpdateZTPOffer, construct temporary new neighbor structure with values from LIE, if no current neighbor exists then set neighbor to new neighbor, PUSH NewNeighbor event, CHECK_THREE_WAY else
    1. if current neighbor system ID differs from LIE's system ID then PUSH MultipleNeighbors else
    2. if current neighbor stored level differs from LIE's level then PUSH NeighborChangedLevel else
    3. if current neighbor stored IPv4/v6 address differs from LIE's address then PUSH NeighborChangedAddress else
    4. if any of neighbor's flood address port, name, local LinkID changed then PUSH NeighborChangedMinorFields
5. CHECK_THREE_WAY
```
Is step #5 unconditional? That is to say, if it is the case that "no current neighbor exists", then after doing "set neighbor to new neighbor, PUSH NewNeighbor event, CHECK_THREE_WAY", do we skip step #5 (and hence do not do a second CHECK_THREE_WAY) or do we also do step #5 (and do a second CHECK_THREE_WAY).

Another way to phrase this question: Where does the "else" at the end of step #4 lead to? Does it lead to substep #1 or step #5? If it does lead to substep #1, where does the end of substep #4 lead? Does it fall down to step #5 or simply end `PROCESS_LIE` altogether. According to how `rift-python` is actually implemented, it seems that the answer is that the "else" goes to substep #1, and substep #4 does fall down to step #5. In that case, I propose the following change

```
4. PUSH UpdateZTPOffer, construct temporary new neighbor structure with values from LIE,
    1. if no current neighbor exists then set neighbor to new neighbor, PUSH NewNeighbor event, CHECK_THREE_WAY else
    2. if current neighbor system ID differs from LIE's system ID then PUSH MultipleNeighbors else
    3. if current neighbor stored level differs from LIE's level then PUSH NeighborChangedLevel else
    4. if current neighbor stored IPv4/v6 address differs from LIE's address then PUSH NeighborChangedAddress else
    5. if any of neighbor's flood address port, name, local LinkID changed then PUSH NeighborChangedMinorFields, CHECK_THREE_WAY
```

- Additionally, when it is stated to "construct temporary new neighbor structure with values from LIE", what is a "neighbor structure"? It seems like a "neighbor structure" is just all the fields from a LIE packet (from both the packet's header and body, as well as the ip addresses the packet originated from). This is somewhat confusing, since "Neighbor" is already a struct defined in the `common.thrift` file and does not contain all the fields referenced.

- When defining `CHECK_THREE_WAY`, for consistentcy, the line "if current state is OneWay do nothing else" should be numbered "1.", and then have "1. if LIE packet does not contain neighbor then if current state is ThreeWay then PUSH NeighborDroppedReflection else" actually be numbered as "2." and so on.

- It would massively improve readability if the "code" prose sections were instead written as pseudocode and were written in a monospace font. Additionally, "proper nouns", such as "PROCESS_LIE" or "IllegalSystemID" should also be formatted as inline code (which, given the presense of the backticks surrounding them, suggests that the spec is actually a markdown document, which supports inline code formatting!)

Suppose that no current neighbor exists, does this mean that the "CHECK_THREE_WAY" procedure would occur twice? 

- In step 3. for `PROCESS_LIE`, how should one implement "remote level is lower than HAT" if the HAT is currently undefined. Does undefined level count as lower than all other levels? 

- The ZTP specific terminology should be defined sooner, since terms such as HAL, HAT, and HALS appear earlier than Section 4.2.7.1. Alternatively, please include a link to the definition when these terms are introduced.


# Rift Python
- two_by_two_by_two_ztp.yaml has `level: superspine`. However, this does not appear to be a real named level value, and attempting to get rift-python to parse the file results in an error.