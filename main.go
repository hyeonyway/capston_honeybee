package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64 -type event bpf monitoring.c -- -I../headers

// eBPF 이벤트 데이터 구조체
type uafEvent struct {
	Timestamp uint64
	Addr      uint64
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

	// Attach kprobe to kfree_skb
	tp, err := link.Tracepoint("skb", "kfree_skb", objs.TraceKfreeSkb, nil)
	if err != nil {
		log.Fatalf("Failed to attach kprobe to kfree_skb: %v", err)
	}
	defer tp.Close()

	// Attach kprobe to __netif_receive_skb_core
	tp2, err := link.Tracepoint("net", "net_dev_xmit", objs.TraceNetDevXmit, nil)
	if err != nil {
		log.Fatalf("Failed to attach tracepoint to net_dev_xmit: %v", err)
	}
	defer tp2.Close()

	fmt.Println("eBPF UAF detection running... Press Ctrl+C to stop.")

	// Signal handling for graceful exit
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Open a ringbuf reader from the userspace RINGBUF map
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	// Graceful exit on signal
	go func() {
		<-stopper
		if err := rd.Close(); err != nil {
			log.Fatalf("Closing ringbuf reader: %s", err)
		}
	}()

	log.Println("Waiting for events..")

	// Event loop
	var event uafEvent
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
		if err == nil {
			log.Printf("[ALERT] UAF detected! SKB reused at address: %x\n", event.Addr)
		}
	}
}
