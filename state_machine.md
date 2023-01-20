// in one way
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

// in two way
on NeighborChangedAddress -> OneWay: no action
on LieRcvd                -> TwoWay: PROCESS_LIE
on UpdateZTPOffer         -> TwoWay: send offer to ZTP FSM
on HoldtimeExpired        -> OneWay: no action
on MTUMismatch            -> OneWay: no action
on UnacceptableHeader     -> OneWay: no action
on ValidReflection        -> ThreeWay: no action
on SendLie                -> TwoWay: SEND_LIE
on HATChanged             -> TwoWay: store HAT
on HALChanged             -> TwoWay: store new HAL
on LevelChanged           -> TwoWay: update level with event value
on FloodLeadersChanged    -> TwoWay: update `you_are_flood_repeater` LIE elements based on flood leader election results
on NewNeighbor            -> MultipleNeighborsWait: PUSH SendLie event
on TimerTick              -> TwoWay: PUSH SendLie event, if last valid LIE was received more than `holdtime` ago as advertised by neighbor then PUSH HoldtimeExpired event
on NeighborChangedLevel   -> OneWay: no action
on MultipleNeighbors      -> MultipleNeighborsWait: start multiple neighbors timer with interval `multiple_neighbors_lie_holdtime_multipler` * `default_lie_holdtime`
on HALSChanged            -> TwoWay: store HALS

// in three way
on NeighborChangedAddress    -> OneWay: no action
on ValidReflection           -> ThreeWay: no action
on HoldtimeExpired           -> OneWay: no action
on UnacceptableHeader        -> OneWay: no action
on NeighborDroppedReflection -> TwoWay: no action
on HALChanged                -> ThreeWay: store new HAL
on MultipleNeighbors         -> MultipleNeighborsWait: start multiple neighbors timer with interval `multiple_neighbors_lie_holdtime_multipler` * `default_lie_holdtime`
on LevelChanged              -> OneWay: update level with event value
on HALSChanged               -> ThreeWay: store HALS
on TimerTick                 -> ThreeWay: PUSH SendLie event, if last valid LIE was received more than `holdtime` ago as advertised by neighbor then PUSH HoldtimeExpired event
on HATChanged                -> ThreeWay: store HAT
on UpdateZTPOffer            -> ThreeWay: send offer to ZTP FSM
on LieRcvd                   -> ThreeWay: PROCESS_LIE
on NeighborChangedLevel      -> OneWay: no action
on SendLie                   -> ThreeWay: SEND_LIE
on FloodLeadersChanged       -> ThreeWay: update `you_are_flood_repeater` LIE elements based on flood leader election results, PUSH SendLie
on MTUMismatch               -> OneWay: no action

// in multiple neighbors wait
on HoldtimeExpired              -> MultipleNeighborsWait: no action
on LieRcvd                      -> MultipleNeighborsWait: no action
on NeighborDroppedReflection    -> MultipleNeighborsWait: no action
on MTUMismatch                  -> MultipleNeighborsWait: no action
on NeighborChangedBFDCapability -> MultipleNeighborsWait: no action
on LevelChanged                 -> OneWay: update level with event value
on SendLie                      -> MultipleNeighborsWait: no action
on UpdateZTPOffer               -> MultipleNeighborsWait: send offer to ZTP FSM
on MultipleNeighborsDone        -> OneWay: no action
on HATChanged                   -> MultipleNeighborsWait: store HAT
on NeighborChangedAddress       -> MultipleNeighborsWait: no action
on HALSChanged                  -> MultipleNeighborsWait: store HALS
on HALChanged                   -> MultipleNeighborsWait: store new HAL
on MultipleNeighbors            -> MultipleNeighborsWait: start multiple neighbors timer with interval `multiple_neighbors_lie_holdtime_multipler` * `default_lie_holdtime`
on FloodLeadersChanged          -> MultipleNeighborsWait: update `you_are_flood_repeater` LIE elements based on flood leader election results
on ValidReflection              -> MultipleNeighborsWait: no action
on TimerTick                    -> MultipleNeighborsWait: check MultipleNeighbors timer, if timer expired PUSH MultipleNeighborsDone
on UnacceptableHeader           -> MultipleNeighborsWait: no action

// other
on Entry into OneWay: CLEANUP