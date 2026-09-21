package cell

const (
	CircWindowStart   = 1000
	CircWindowInc     = 100
	StreamWindowStart = 500
	StreamWindowInc   = 50
)

func NeedSendme(deliver, start, inc int) bool {
	return deliver <= start-inc
}
