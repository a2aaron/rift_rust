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

- In LIE Exchange, when doing "send offer to ZTP FSM" specifically mean?
    - Do we use the value stored for "neighbor"? If so, this means CLEANUP would "clear" the values stored for neighbor. If not, do we just use the values from the most recent valid LIE packet, even if we have not formed an adjacency with the node?
    - How does this interact with the holdtime? If the holdtime expires, should we send the offer with an UNDEFINED_LEVEL? Or should we continue to send the offer with the level that the LIE packet contained?
    - When, precisely, does an offer expire?

- What is the purpose of the LIE events `HALChanged` and `HALSChanged`? Specifically: Why are these events _in the LIE FSM_ if they do not appear to affect the LIE FSM's behavior, and are exclusively sent by the ZTP FSM? The `HATChanged` event _does_ appear to have an effect, since leaf level nodes are not allowed to form more than one neighbor to HAT nodes. It seems like HAL and HALS should become concepts that only the ZTP FSM cares about.

- `LEVEL_COMPUTE` is defined as "compute best offered or configured level and HAL/HAT, if anything changed PUSH ComputationDone", however, it seems that rift-python always unconditionally pushes ComputationDone. Why does the spec differ here?

- `BetterHAL` and `BetterHAT` could probably be merged together?

- The procedure for `PROCESS_LIE` and the conditions for adjacency formation in Section 4.2.2 conflict with each other. Specficially:

Step 3 of PROCESS_LIE states:
```
if LIE has undefined level OR 
this node's level is undefined OR
this node is a leaf and remote level is lower than HAT OR
(LIE's level is not leaf AND its difference is more than one from this node's level)
then CLEANUP, PUSH UpdateZTPOffer, PUSH UnacceptableHeader else
```

Condition 6 of the adjacency formation rules states:

```
6. [
     i) the node is at `leaf_level` value and has no ThreeWay adjacencies already to nodes
        at Highest Adjacency ThreeWay (HAT as defined later in Section 4.2.7.1) with level
        different than the adjacent node *or
     ii) the node is not at `leaf_level` value and the neighboring node is at `leaf_level` value *or*
     iii) both nodes are at `leaf_level` values *and* both indicate support for Section 4.3.9 *or*
     iv) neither node is at `leaf_level` value and the neighboring node is at most one level difference away
]
```

Suppose node A is a leaf received a LIE from node B that is level 23. Let node A have no other adjacencies. The adjacency formation rules would allow an adjancy to be formed between node A and node B (specifically: 6.i allows this since node A is at leaf level and has no other ThreeWay adjacencies already). However, `PROCESS_LIE` would not allow this. This is because `(LIE's level is not leaf AND its difference is more than one from this node's level)` is false--node B has level 23 while node A has level 0, so their difference is more than 1. Hence, this would only allow node B to be eligable to form an adjacency with node A, but node A is not eligable (meaning node B would only ever be able to be in TwoWay with node A and node A will always reject node B's LIEs)

# TIE Exchange
- why is there `tie_been_acked` and `remove_from_all_queues` if they do the same thing??

- MAX_TIEID states that it's constants are the following:
```
TIE Key with maximal values:
TIEID(originator=MAX_UINT64,
tietype=TIETypeMaxValue, tie_nr=MAX_UINT64,
direction=North)
```
However, Thrift does not have unsigned integers (the best we can do are signed 64bit integers), so assigning `originator` a value of `MAX_UINT64` is impossible. Additionally, `tie_nr` is actually a 32bit signed integer, so assigning it a value of `MAX_UINT64` is even more impossible.
- what the heck is "TIEDB"? it only shows up in TIDE Generation (Section 4.2.3.3.1.2.1)
- Section 4.2.3.3.1.1 FloodState Structure per Adjacency: "The structure contains conceptually on each adjacency the following elements." should probably be instead: "Conceptually, each adjacency contains a structure with the following elements."

- Section 4.2.3.3.1.2.1. TIDE Generation
    - In the pseudocode, the variable `TIDE_START` is defined but not used anywhere.
    - In the pseudocode, step 5 says to send sorted headers. Should `HEADERS` be sorted at that time or be sorted also for steps 3 and 4?

- Section 4.2.3.3.1.2.2  TIDE Processing
    - `REQKEYS` and `CLEARKEYS` are collections of `TIEID`s but seemingly have TieHeaders inserted into them?
    - What am i calling `bump_own_tie` on?

- Section 4.2.3.3 Flooding
```
TIEs are uniquely identifed by `TIEID` schema element. `TIEID` space is a total order achieved by comparing the elements in sequence defined in the element and comparing each value as an unsigned integer of according length. They contain a `seq_nr` element to distinguish newer versions of same TIE. TIEIDs also carry `origination_time` and `origination_lifetime`. Field `origination_time` contains the absolute timestamp when the TIE was generated. Field `origination_lifetime` carries lifetime when the TIE was generated. Those are normally disregarded during comparison and carried purely for debugging/security purposes if present. They may be used for comparison of last resort to differentiate otherwise equal ties and they can be used on fabrics with synchronized clock to prevent lifetime modification attacks.
```
First off, what the heck does "comparing the elements in sequence defined in the element and comparing each value as an unsigned integer of according length" mean? Do you mean "compare TIEIDs lexiographically, interpreting each field as an unsigned integer and having the following ordering for fields: `direction`, `originator`, `tietype`, `tie_nr`? It should be noted that Thrift doesn't have unsigned ints, making this annoying to do with autogenerated code.

Second, "TIEIDs also carry `origination_time` and `origination_lifetime`" is not true! Only the TieHeader carries those fields!

Third, are TieHeaders also totally ordered? It seems like they are, but this should be made explicit.

- It is really unclear what sort of structure the "queues" are supposed to be. Are they:
    - storing _just_ TIEIDs?
    - storing _just_ TieHeaders?
    - storing TIEID -> TieHeader key-value pairs? If so, is it the TIEID that determines uniqueness (and hence there should not be two TieHeaders of the same TIEID even if they have different other values?)
    - In particular, what does "if TIE" with same key is found on TIES_ACK" mean for `try_to_transmit_tie`?
# Rift Python
- two_by_two_by_two_ztp.yaml has `level: superspine`. However, this does not appear to be a real named level value, and attempting to get rift-python to parse the file results in an error.
- Should ZTP really set the `_derived_level` value directly instead of issuing `LEVEL_CHANGED`? This means that ZTP level changes don't cause the LIE FSM to reset back to `ONE_WAY`, even though `LEVEL_CHANGED` does...