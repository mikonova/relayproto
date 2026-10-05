package types

const (
	Message = iota
	MessageReceived
	RelayError
	RelaySuccess
	RelayTimeout
	RequestIp
	IpCarrier
	OnReceiveConfirm
	OnReceiveFail
	ClientHello
	ServerHello
	ClientConfirmed
)
