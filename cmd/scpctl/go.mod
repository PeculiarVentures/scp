module github.com/PeculiarVentures/scp/cmd/scpctl

go 1.22

require (
	github.com/PeculiarVentures/scp v0.0.0
	github.com/PeculiarVentures/scp/transport/pcsc v0.0.0
)

require github.com/ebfe/scard v0.0.0-20230420082256-7db3f9b7c8a7 // indirect

replace (
	github.com/PeculiarVentures/scp => ../..
	github.com/PeculiarVentures/scp/transport/pcsc => ../../transport/pcsc
)
