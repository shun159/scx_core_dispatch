module scx_core_dispatch

go 1.22.4

require (
	github.com/cilium/ebpf v0.15.0
	github.com/pkg/errors v0.9.1
)

require golang.org/x/sys v0.26.0 // indirect

replace github.com/cilium/ebpf => ../ebpf/
