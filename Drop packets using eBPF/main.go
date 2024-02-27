package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const (
	InterfaceName = "eth0" // Change this to your interface name
	ProgramName   = "xdp_dilih"
	MapName       = "output_map"
)

type PacketEvent struct {
	TimeSinceBoot  uint64
	ProcessingTime uint32
	Type           uint8
}

func main() {
	// Load eBPF program
	coll, err := ebpf.LoadCollection("bpf/dilih_kern.o")
	if err != nil {
		panic(fmt.Errorf("failed to load eBPF collection: %w", err))
	}
	defer coll.Close()

	prog := coll.Programs[ProgramName]
	if prog == nil {
		panic(fmt.Errorf("program %s not found", ProgramName))
	}

	// Attach eBPF program to interface
	iface := os.Getenv("INTERFACE")
	if iface == "" {
		iface = InterfaceName
	}
	ifaceIndex, err := net.InterfaceByName(iface)
	if err != nil {
		panic(fmt.Errorf("failed to get interface %s: %w", iface, err))
	}

	opts := link.AttachOptions{
		Program:   prog,
		Interface: ifaceIndex.Index,
	}
	if err := link.AttachProgram(opts); err != nil {
		panic(fmt.Errorf("failed to attach program to interface: %w", err))
	}

	fmt.Println("Successfully loaded and attached eBPF program.")

	// Create map for handling packet events
	outputMap := coll.Maps[MapName]
	if outputMap == nil {
		panic(fmt.Errorf("map %s not found", MapName))
	}

	// Start processing packet events
	go func() {
		for {
			// Read packet events from map
			iter := outputMap.Iterate()
			for {
				key, value, next := iter.Next()
				if next {
					var event PacketEvent
					if err := binary.Read(value, binary.LittleEndian, &event); err != nil {
						fmt.Println("Error reading packet event:", err)
						continue
					}

					// Process packet event
					fmt.Printf("Received packet event: %+v\n", event)
				} else {
					break
				}
			}
			iter.Close()

			time.Sleep(time.Second) // Adjust the sleep duration as needed
		}
	}()

	// Wait for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
}
