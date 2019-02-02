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
		handshake_protocol := pLoad[5]

		// Only try client hellos
		if handshake_protocol == 0x1 {
			offset, base_offset, extension_offset := uint16(0), uint16(43), uint16(2)

			// Get the length of the session ID
			session_id_len := uint16(pLoad[base_offset])

			// Get the length of the ciphers
			cipher_len_start := base_offset + session_id_len + 1
			cipher_len := binary.BigEndian.Uint16(pLoad[cipher_len_start : cipher_len_start+2])
			offset = base_offset + session_id_len + cipher_len + 2

			// Get the length of the compression methods list
			compression_len := uint16(pLoad[offset+1])
			offset += compression_len + 2

			// Get the length of the extensions
			extensions_len := binary.BigEndian.Uint16(pLoad[offset : offset+2])

			// Add the full offset to were the extensions start
			extension_offset += offset

			for extension_offset < extensions_len {
				extension_id := binary.BigEndian.Uint16(pLoad[extension_offset : extension_offset+2])
				extension_offset += 2

				extension_len := binary.BigEndian.Uint16(pLoad[extension_offset : extension_offset+2])
				extension_offset += 2

				if extension_id == 0 {
					// We don't need the server name list length or name_type, so skip that
					extension_offset += 3

					// Get the length of the domain name
					name_length := binary.BigEndian.Uint16(pLoad[extension_offset : extension_offset+2])
					extension_offset += 2

					domain_name := string(pLoad[extension_offset : extension_offset+name_length])
					fmt.Println(domain_name)

					if domain_name == domainToBlock {
						p.Drop()
						return
					}
				}

				extension_offset += extension_len
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
