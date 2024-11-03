package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/pkg/errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 bpf bpf/sched_ext.bpf.c -- -Wno-compare-distinct-pointer-types -Wno-int-conversion -Wnull-character -g -c -O2 -D__KERNEL__

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", errors.WithStack(err))
	}
	defer objs.Close()

	m := objs.SimpleSched1
	l, err := link.AttachRawLink(link.RawLinkOptions{
		ProgramFd: m.FD(),
		Target:    0,
		Attach:    ebpf.AttachStructOps,
	})

	if err != nil {
		log.Fatalf("failed to attach sched_ext: %s", err)
	}
	defer l.Close()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	<-stopper

	log.Print("quit sched_ext")
}
