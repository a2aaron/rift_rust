# Spec Confusions

## LIE Exchange
- The FSM diagram for LIE exchange is really confusing to read. A version where the labels are closer to the arrows and the arrows do not overlap each other would be nice
    - A simplified FSM diagram showing just the "happy path" would be useful for this as well
- **The list of "action"s in the LIE exchange should really be a table, not freeform prose.**
- **The description for `CHECK_THREE_WAY` appears to be completely wrong**. It reads as:
```
- CHECK_THREE_WAY: if current state is OneWay do nothing else
 1. if LIE packet does not contain neighbor then if current state is ThreeWay then PUSH NeighborDroppedReflection else
 2. if packet reflects this system's ID and local port and state is ThreeWay then PUSH event ValidReflection else PUSH event MultipleNeighbors
```
However, this means that it is impossible for `ValidReflection` to be pushed while in `TwoWay`, which
seems obviously wrong since `ValidReflection` is the only way to get from `TwoWay` to `ThreeWay`.

Additionally, `rift-python` significantly deviates from the spec. Here is the relevant code:
```py
def check_three_way(self):
    # Section B.1.5
    # CHANGE: This is a little bit different from the specification
    # (see comment [CheckThreeWay])
    if self.fsm.state == self.State.ONE_WAY:
        pass
    elif self.fsm.state == self.State.TWO_WAY:
        if self.neighbor_lie.neighbor_system_id is None:
            pass
        elif self.check_reflection():
            self.fsm.push_event(self.Event.VALID_REFLECTION)
        else:
            self.fsm.push_event(self.Event.MULTIPLE_NEIGHBORS)
    else: # state is THREE_WAY
        if self.neighbor_lie.neighbor_system_id is None:
            self.fsm.push_event(self.Event.NEIGHBOR_DROPPED_REFLECTION)
        elif self.check_reflection():
            pass
        else:
            self.fsm.push_event(self.Event.MULTIPLE_NEIGHBORS)
```
As written, it seems `rift-python` implements `CHECK_THREE_WAY` as follows:
```
- CHECK_THREE_WAY
1. If current state is OneWay, do nothing
2. Else if current state is TwoWay, then if the LIE packet has a valid reflection, then PUSH ValidReflection, otherwise PUSH MultipleNeighbors
3. Else if current state is ThreeWay, then if the LIE packet has no neighbor, PUSH NeighborDroppedReflection, otherwise PUSH MultipleNeighbors
```

- Additionally, the table should group similar events together. For example, HALChanged, HALSChanged, and HATChanged should all be next to each other.

- It would be nice if the event list was seperated into "external" and "internal" events. Some events, such as TimerTick, only occur due to outside sources providing the event. In that sense, they are "external". Other events, such as "SendLie" or "ValidReflection" are only encountered via PUSH Event procedures, which themselves are only ever done by actions. In that sense, they are "internal". It would be nice if those were clearly seperated, so it is easier to see how the FSM interacts with the rest of the RIFT system.

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

- In the action list for MultipleNeighborsWait, there is the following:
```
on NeighborChangedBFDCapability in MultipleNeighborsWait finishes in MultipleNeighborsWait: no action
```

What the heck is "NeighborChangedBFDCapability"? This doesn't appear in the list of events. It _does_ appear in the state transition diagram, but it seems that it is impossible for this event to be issued, since nothing else in the spec talks about it.

- More clarity on what counts as a "valid LIE". The spec says "passing all checks for adjacency formation while disregarding all clauses involving level values". It would be nice to know explicitly, which checks should be considered or not considered for a LIE to be valid (is this bullet points 1 through 4 for when the spec says "A node MUST form a ThreeWay adjacency (or in other words consider the neighbor "valid" and hence reflecting it) if and only if the following first order logic conditions are satisfied on a LIE packet as specified by the `LIEPacket` schema element and received on a link" at 4.2.2?)

- ZTP FSM diagram contains two Enter arrows, but initial state is defined as ComputeBestOffer.

- In the definition for PURGE_OFFERS, "COMPARE_OFFERS" is spelled "COMPARE OFFERS" (the underscore is missing)

- In the definition for COMPARE_OFFERS, what does it mean to "return" the events BetterHAL/LostHAL/BetterHAT/LostHAT? Additionally, when are these events "necessary"? It also seems that the there is a word missing.
```
COMPARE_OFFERS: checks whether based on current offers and held last results the events BetterHAL/LostHAL/BetterHAT/LostHAT are necessary and returns them
```

rewrite as:
```
COMPARE_OFFERS: checks whether the events BetterHAL/LostHAL/BetterHAT/LostHAT are necessary and returns them based on current offers and held last results
```
- UPDATE_OFFER: "adjancency" should be spelled as "adjacency". Also, what is an "adjacency holdtime"? Is that the current value of the "adjacency holddown timer"?
- PURGE_OFFERS - Really do REMOVE_OFFER? REMOVE_OFFER already does COMPARE_OFFERS + push events, so this is likely to add tons of extraneous events for no reason. It should probably read "remove all held offers, COMPARE_OFFERS, PUSH according events"

- Why does COMPARE_OFFERS "return events" if those events are always then PUSHed, why not just make COMPARE_OFFERS do the pushing?

- In LIE Exchange, when doing "send offer to ZTP FSM", 
    - Do we use the value stored for "neighbor"? If so, this means CLEANUP would "clear" the values stored for neighbor. If not, do we just use the values from the most recent valid LIE packet, even if we have not formed an adjacency with the node?
    - how does this interact with the holdtime? If the holdtime expires, should we send the offer with an UNDEFINED_LEVEL? Or should we continue to send the offer with the level that the LIE packet contained?

# Rift Python
- two_by_two_by_two_ztp.yaml has `level: superspine`. However, this does not appear to be a real named level value, and attempting to get rift-python to parse the file results in an error.