package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/Telefonica/nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Queue struct {
	id    uint16
	queue *nfqueue.Queue
}

func NewQueue(id uint16) *Queue {
	q := &Queue{
		id: id,
	}
	queueCfg := &nfqueue.QueueConfig{
		MaxPackets: 1000,
		BufferSize: 16 * 1024 * 1024,
		QueueFlags: []nfqueue.QueueFlag{nfqueue.FailOpen},
	}
	q.queue = nfqueue.NewQueue(q.id, q, queueCfg)
	return q
}

// Start the queue
func (q *Queue) Start() error {
	return q.queue.Start()
}

// Stop the queue.
func (q *Queue) Stop() error {
	return q.queue.Stop()
}

var domainToBlock string

// Handle a nfqueue packet. It implements nfqueue.PacketHandler interface.
func (q *Queue) Handle(p *nfqueue.Packet) {
	ipLayer := gopacket.NewPacket(p.Buffer, layers.LayerTypeIPv4, gopacket.NoCopy)

	if tcpLayer := ipLayer.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		pLoad := tcp.Payload

		if len(pLoad) < 10 {
			p.Accept()
			return
		}

		if pLoad[0] != 0x16 {
			p.Accept()
			return
		}

		//handshake_len := binary.BigEndian.Uint16(pLoad[3:5]) + 5
		handshakeProtocol := pLoad[5]

		// Only try client hellos
		if handshakeProtocol == 0x1 {
			offset, baseOffset, extensionOffset := uint16(0), uint16(43), uint16(2)

			// Get the length of the session ID
			sessionIdLen := uint16(pLoad[baseOffset])

			// Get the length of the ciphers
			cipherLenStart := baseOffset + sessionIdLen + 1
			cipherLen := binary.BigEndian.Uint16(pLoad[cipherLenStart : cipherLenStart+2])
			offset = baseOffset + sessionIdLen + cipherLen + 2

			// Get the length of the compression methods list
			compressionLen := uint16(pLoad[offset+1])
			offset += compressionLen + 2

			// Get the length of the extensions
			extensionsLen := binary.BigEndian.Uint16(pLoad[offset : offset+2])

			// Add the full offset to were the extensions start
			extensionOffset += offset

			for extensionOffset < extensionsLen {
				extensionId := binary.BigEndian.Uint16(pLoad[extensionOffset : extensionOffset+2])
				extensionOffset += 2

				extensionLen := binary.BigEndian.Uint16(pLoad[extensionOffset : extensionOffset+2])
				extensionOffset += 2

				if extensionId == 0 {
					// We don't need the server name list length or name_type, so skip that
					extensionOffset += 3

					// Get the length of the domain name
					nameLength := binary.BigEndian.Uint16(pLoad[extensionOffset : extensionOffset+2])
					extensionOffset += 2

					domainName := string(pLoad[extensionOffset : extensionOffset+nameLength])
					fmt.Println(domainName)

					if domainName == domainToBlock {
						p.Drop()
						return
					}
				}

				extensionOffset += extensionLen
			}
		}
	}

	p.Accept()
}

func main() {
	flag.StringVar(&domainToBlock, "domain", "", "Domain to block")
	queueId := *flag.Uint("queue", 1, "Queue ID")

	flag.Parse()

	if domainToBlock == "" {
		fmt.Println("You must enter a domain")
		return
	}

	q := NewQueue(uint16(queueId))
	q.Start()
	wait := make(chan bool)
	<-wait
}
