package tray

// State is the coarse client state the notification-area icon shows. The icon
// is the answer to "is my traffic going through a node right now?" and it has
// to be readable at 16x16 without a tooltip, so the state is a colour, not a
// string.
type State int

const (
	// StateUnknown is the state before the client has finished starting.
	StateUnknown State = iota
	// StateStopped means the client is not serving anything.
	StateStopped
	// StateDirect means the client is running but the system proxy is off:
	// traffic leaves the machine directly.
	StateDirect
	// StateProxy means the system proxy is on: traffic uses the node.
	StateProxy
	// StateError means the last switch failed and the icon is telling the user
	// to look at the log.
	StateError
)
