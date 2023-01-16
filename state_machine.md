on TimerTick                  -> OneWay: PUSH SendLie event
on UnacceptableHeader         -> OneWay: no action
on LevelChanged               -> OneWay: update level with event value, PUSH SendLie event
on NeighborChangedMinorFields -> OneWay: no action
on NeighborChangedLevel       -> OneWay: no action
on NewNeighbor                -> TwoWay: PUSH SendLie event
on HoldtimeExpired            -> OneWay: no action
on HALSChanged                -> OneWay: store HALS
on NeighborChangedAddress     -> OneWay: no action
on LieRcvd                    -> OneWay: PROCESS_LIE
on ValidReflection            -> ThreeWay: no action
on SendLie                    -> OneWay: SEND_LIE
on UpdateZTPOffer             -> OneWay: send offer to ZTP FSM
on HATChanged                 -> OneWay: store HAT
on MultipleNeighbors          -> MultipleNeighborsWait: start multiple neighbors timer with interval `multiple_neighbors_lie_holdtime_multipler` * `default_lie_holdtime`
on MTUMismatch                -> OneWay: no action
on FloodLeadersChanged        -> OneWay: update `you_are_flood_repeater` LIE elements based on flood leader election results
on NeighborDroppedReflection  -> OneWay: no action
on HALChanged                 -> OneWay: store new HAL