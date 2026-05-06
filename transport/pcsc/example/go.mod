module demo

go 1.26.2

replace github.com/PeculiarVentures/scp/transport/pcsc => ..

replace github.com/PeculiarVentures/scp => ../../..

require (
	github.com/PeculiarVentures/scp v0.0.0
	github.com/PeculiarVentures/scp/transport/pcsc v0.0.0-00010101000000-000000000000
)

require github.com/ebfe/scard v0.0.0-20230420082256-7db3f9b7c8a7 // indirect
