package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/Lochnair/go-patricia/patricia"
	"github.com/Telefonica/nfqueue"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/shomali11/util/xstrings"
	"golang.org/x/net/idna"
	"os"
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

// Handle a nfqueue packet. It implements nfqueue.PacketHandler interface.
func (q *Queue) Handle(p *nfqueue.Packet) {
	ipLayer := gopacket.NewPacket(p.Buffer, layers.LayerTypeIPv4, gopacket.NoCopy)

	if tcpLayer := ipLayer.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		payload := tcp.Payload
		payloadLength := uint16(len(payload))

		if len(payload) < 10 {
			IfElseDoAction(acceptOnError, p.Accept, p.Drop)
			return
		}

		if payload[0] != 0x16 {
			p.Accept()
			return
		}

		handshakeLength := binary.BigEndian.Uint16(payload[3:5]) + 5
		handshakeProtocol := payload[5]

		// Only attempt to match on client hellos
		if handshakeProtocol != 0x01 {
			p.Accept()
			return
		}

		// If we don't have all the data, try matching with what we have
		if handshakeLength > payloadLength {
			handshakeLength = payloadLength
		}

		offset, baseOffset, extensionOffset := uint16(0), uint16(43), uint16(2)

		if baseOffset + 2 > uint16(len(payload)) {
			IfElseDoAction(acceptOnError, p.Accept, p.Drop)
			return
		}

		// Get the length of the session ID
		sessionIdLength := uint16(payload[baseOffset])

		if (sessionIdLength + baseOffset + 2) > handshakeLength {
			IfElseDoAction(acceptOnError, p.Accept, p.Drop)
			return
		}

		// Get the length of the ciphers
		cipherLenStart := baseOffset + sessionIdLength + 1
		cipherLen := binary.BigEndian.Uint16(payload[cipherLenStart : cipherLenStart+2])
		offset = baseOffset + sessionIdLength + cipherLen + 2

		if offset > handshakeLength {
			IfElseDoAction(acceptOnError, p.Accept, p.Drop)
			return
		}

		// Get the length of the compression methods list
		compressionLen := uint16(payload[offset+1])
		offset += compressionLen + 2

		if offset > handshakeLength {
			IfElseDoAction(acceptOnError, p.Accept, p.Drop)
			return
		}

		// Get the length of the extensions
		extensionsLen := binary.BigEndian.Uint16(payload[offset : offset+2])

		// Add the full offset to were the extensions start
		extensionOffset += offset

		if extensionsLen > handshakeLength {
			IfElseDoAction(acceptOnError, p.Accept, p.Drop)
			return
		}

		for extensionOffset < extensionsLen {
			extensionId := binary.BigEndian.Uint16(payload[extensionOffset : extensionOffset+2])
			extensionOffset += 2

			extensionLen := binary.BigEndian.Uint16(payload[extensionOffset : extensionOffset+2])
			extensionOffset += 2

			if extensionId == 0 {
				// We don't need the server name list length or name_type, so skip that
				extensionOffset += 3

				// Get the length of the domain name
				nameLength := binary.BigEndian.Uint16(payload[extensionOffset : extensionOffset+2])
				extensionOffset += 2

				domainName := string(payload[extensionOffset : extensionOffset+nameLength])
				reversedDomain := xstrings.Reverse(domainName)
				_, _, found, leftover := domainTrie.FindSubtree(patricia.Prefix(reversedDomain))

				/*
				 * Match is true if either the domain matches perfectly in the Trie
				 * or if the first character of the leftover is a wildcard
				 */
				match := found || (len(leftover) > 0 && leftover[0] == 42)
				IfElseDoAction(match, p.Drop, p.Accept)
				break
			}

			extensionOffset += extensionLen
		}
	}
}

func IfElseDoAction(condition bool, a func() error, b func() error) {
	var err error

	if condition {
		err = a()
	} else {
		err = b()
	}

	if err != nil {
		fmt.Println("An error occurred: " + err.Error())
	}
}

func loadDomainsFromFile(path *string) {
	file, err := os.Open(*path)

	if err != nil {
		fmt.Println("Error: Couldn't open specified file: " + err.Error())
		return
	}

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		punycode, err := idnaProfile.ToASCII(scanner.Text())

		if err != nil {
			fmt.Printf("An error occurred while converting domain %s to punycode: %s\n", scanner.Text(), err.Error())
			continue
		}

		reversedDomain := xstrings.Reverse(punycode)
		domainTrie.Insert(patricia.Prefix(reversedDomain), 0)
	}
}

var acceptOnError bool
var domainTrie *patricia.Trie
var idnaProfile *idna.Profile

func main() {
	filePath := flag.String("f", "", "File containing domains to block")
	queueId := *flag.Uint("queue", 1, "Queue ID")
	flag.BoolVar(&acceptOnError, "k", true, "Accept if there's an error")

	flag.Parse()

	if *filePath == "" {
		fmt.Println("You must specify a file")
		flag.Usage()
		return
	}

	/**
	 * Use standard lookup profile
	 * except for strict domain name validation
	 * so we can convert domains with wildcards in them
	 */
	idnaProfile = idna.New(
		idna.MapForLookup(),
		idna.Transitional(true),
		idna.StrictDomainName(false))

	domainTrie = patricia.NewTrie()
	loadDomainsFromFile(filePath)

	q := NewQueue(uint16(queueId))

	if err := q.Start(); err != nil {
		fmt.Println("Severe: Error upon starting queue: " + err.Error())
		return
	}

	// Make use of channels to prevent the program from exiting prematurely
	<-make(chan bool)
}
