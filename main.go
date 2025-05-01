package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/ebpf/ringbuf"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 -type event bpf monitoring.c -- -I../headers

type bpfUafEvent struct {
	SkbAddr uint64
	Verdict int32
	_       [4]byte // padding
}

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled eBPF programs and maps.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	kp1, err := link.Kprobe("nf_hook_slow", objs.SaveSkb, nil)
	if err != nil {
		log.Fatalf("Kprobe nf_hok_slow: %v", err)
	}
	defer kp1.Close()


	kp2, err := link.Kprobe("kfree_skb", objs.MarkFreedSkb, nil)
	if err != nil {
		log.Fatalf("Kprobe kfree_skb: %v", err)
	}
	defer kp2.Close()

	kret, err := link.Kretprobe("nf_hook_slow", objs.CheckVerdict, nil)
	if err != nil {
		log.Fatalf("Kretprobe nf_hook_slow: %v", err)
	}
	defer kret.Close()

	// ring buffer reader
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("creating ringbuf reader: %s", err)
	}
	defer rd.Close()

	fmt.Println("eBPF UAF detection running... Press Ctrl+C to stop.")

	// ring buffer consumer goroutine
	go func() {
		var event bpfUafEvent
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Received signal, exiting..")
					return
				}
				log.Printf("Reading from reader: %s", err)
				continue
			}
			err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
			if(err == nil) {
				fmt.Printf("[UAF DETECTED] skb=0x%x verdict=%d\n", event.SkbAddr, event.Verdict)
			}
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("Exiting...")
}