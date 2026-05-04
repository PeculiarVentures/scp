module github.com/PeculiarVentures/scp/transport/grpc/example

go 1.22

require (
	github.com/PeculiarVentures/scp v0.4.0
	github.com/PeculiarVentures/scp/transport/grpc v0.0.0
	github.com/PeculiarVentures/scp/transport/pcsc v0.1.0
	google.golang.org/grpc v1.69.0
)

require (
	github.com/ebfe/scard v0.0.0-20230420082256-7db3f9b7c8a7 // indirect
	golang.org/x/net v0.30.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
	golang.org/x/text v0.19.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241015192408-796eee8c2d53 // indirect
	google.golang.org/protobuf v1.36.0 // indirect
)

replace (
	github.com/PeculiarVentures/scp => ../../..
	github.com/PeculiarVentures/scp/transport/grpc => ..
	github.com/PeculiarVentures/scp/transport/pcsc => ../../pcsc
)
