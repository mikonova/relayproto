package types

const (
	Message = iota
	KeyTransmit
	MessageReceived
	RelayError
	RelaySuccess
	RelayTimeout
	RequestID
	IdCarrier
	OnReceiveConfirm
	OnReceiveFail
	ClientHello
	ServerHello
	ClientConfirmed
	ServerInternalError
	ServerMaxConnsReached
)
