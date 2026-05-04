module github.com/PeculiarVentures/scp/transport/grpc/example

go 1.24.0

require (
	github.com/PeculiarVentures/scp v0.4.0
	github.com/PeculiarVentures/scp/transport/grpc v0.0.0
	github.com/PeculiarVentures/scp/transport/pcsc v0.1.0
	google.golang.org/grpc v1.79.3
)

require (
	github.com/ebfe/scard v0.0.0-20230420082256-7db3f9b7c8a7 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/sys v0.39.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
)

replace (
	github.com/PeculiarVentures/scp => ../../..
	github.com/PeculiarVentures/scp/transport/grpc => ..
	github.com/PeculiarVentures/scp/transport/pcsc => ../../pcsc
)
