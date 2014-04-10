package main

import (
	"github.com/coopernurse/gorp"
	dhcp "github.com/krolaw/dhcp4"

	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	_ "github.com/ziutek/mymysql/godrv"
	"log"
	"math/rand"
	"net"
	"os"
	"time"
)

type lease struct {
	nic    net.HardwareAddr // Client's CHAddr
	expiry time.Time        // When the lease expires
}

type staticlease struct {
	nic    net.HardwareAddr
	expiry time.Time
	ip     net.IP
}

var settings struct {
	User     string `json:"user`
	Password string `json:"password"`
	Database string `json:"database"`
}

type DHCPHandler struct {
	ip             net.IP              // Server IP to use
	allowedOptions dhcp.Options        // Options to send to DHCP Clients
	deniedOptions  dhcp.Options        // Options to send to DHCP Clients
	start          net.IP              // Start of IP range to distribute
	leaseRange     int                 // Number of IPs to distribute (starting from start)
	leaseDuration  time.Duration       // Lease period
	leases         map[int]lease       // Map to keep track of leases
	statics        map[int]staticlease // Map to keep track of static leases
	dbmap          *gorp.DbMap
}

type userTable struct {
	Id         int64     `db:"ID"`
	Active     bool      `db:"Active"`
	Room       int32     `db:"Room"`
	Hub_room   int32     `db:"HubRoom"`
	Net        int32     `db:"Net"`
	Mac        string    `db:"MAC"`
	Ip         int32     `db:"IP"`
	First_name string    `db:"first_name"`
	Last_name  string    `db:"last_name"`
	Email      string    `db:"e-mail"`
	Cellphone  string    `db:"cellphone"`
	Username   string    `db:"username"`
	Password   string    `db:"password"`
	Validto    time.Time `db:"validto"`
	Acclevel   string    `db:"acclevel"`
	Comment    string    `db:"comment"`
	Switch     string
	Port       string
	LastEdit   time.Time `db:lastEdit`
	Version    int32
}

// Example using DHCP with a single network interface device
func main() {
	fmt.Println("Lets get this started")
	staticleases, dbmap := initializeStaticLeases()

	serverIP := net.IP{134, 130, 172, 5}
	handler := &DHCPHandler{
		ip:            serverIP,
		leaseDuration: 2 * time.Hour,
		start:         net.IP{192, 168, 172, 3},
		leaseRange:    250,
		leases:        make(map[int]lease, 10),
		statics:       staticleases,
		dbmap:         dbmap,
		deniedOptions: dhcp.Options{
			dhcp.OptionSubnetMask:       []byte{255, 255, 255, 0},
			dhcp.OptionRouter:           []byte(net.IP{192, 168, 172, 2}), // Presuming Server is also your router
			dhcp.OptionDomainNameServer: []byte(net.IP{192, 168, 172, 2}), // Presuming Server is also your DNS server
		},
		allowedOptions: dhcp.Options{
			dhcp.OptionSubnetMask:       []byte{255, 255, 254, 0},
			dhcp.OptionRouter:           []byte(net.IP{134, 130, 172, 1}), // Presuming Server is also your router
			dhcp.OptionDomainNameServer: []byte(net.IP{134, 130, 4, 1}),   // Presuming Server is also your DNS server
		},
	}

	fmt.Println("Everything Ready for the start :)")
	// log.Fatal(dhcp.ListenAndServe(handler))
	log.Fatal(dhcp.ListenAndServeIf("eth0", handler)) // Select interface on multi interface device
}

func (h *DHCPHandler) ServeDHCP(p dhcp.Packet, msgType dhcp.MessageType, options dhcp.Options) (d dhcp.Packet) {

	// The length N gives the total number of octets in the Agent
	// Information Field.  The Agent Information field consists of a
	// sequence of SubOpt/Length/Value tuples for each sub-option, encoded
	// in the following manner:

	//        SubOpt  Len     Sub-option Value
	//       +------+------+------+------+------+------+--...-+------+
	//       |  1   |   N  |  s1  |  s2  |  s3  |  s4  |      |  sN  |
	//       +------+------+------+------+------+------+--...-+------+
	//        SubOpt  Len     Sub-option Value
	//       +------+------+------+------+------+------+--...-+------+
	//       |  2   |   N  |  i1  |  i2  |  i3  |  i4  |      |  iN  |
	//       +------+------+------+------+------+------+--...-+------+
	//
	// The initial assignment of DHCP Relay Agent Sub-options is as follows:

	//              DHCP Agent              Sub-Option Description
	//              Sub-option Code
	//              ---------------         ----------------------
	//                  1                   Agent Circuit ID Sub-option
	//                  2                   Agent Remote ID Sub-option
	// Source: http://tools.ietf.org/html/rfc3046#page-5

	relayAgent := options[dhcp.OptionRelayAgentInformation]
	// log.Printf("Found RelayAgent Information: %v\n", relayAgent)
	log.Printf("Should be Port: %v/%v\n", relayAgent[6], relayAgent[7])
	swHostname := 12 // Circuit ID header + Circuit ID + Remote ID header + string starts after 2
	log.Printf("Should be Switch: %v\n", string(relayAgent[swHostname:]))

	switch msgType {

	case dhcp.Discover:
		log.Printf("DHCPDISCOVER from %v", p.CHAddr())

		free, options := h.giveOutIP(p)

		if free == nil {
			return nil
		}

		return dhcp.ReplyPacket(p, dhcp.Offer, h.ip, free, h.leaseDuration,
			options.SelectOrderOrAll(options[dhcp.OptionParameterRequestList]))

	case dhcp.Request:
		log.Printf("DHCPREQUEST for %v from %v", net.IP(options[dhcp.OptionRequestedIPAddress]).String(), p.CHAddr())
		if server, ok := options[dhcp.OptionServerIdentifier]; ok && !net.IP(server).Equal(h.ip) {
			log.Println("This DHCP packet is not for me!")
			return nil // Message not for this dhcp server
		}
		if reqIP := net.IP(options[dhcp.OptionRequestedIPAddress]); len(reqIP) == 4 {
			if []byte(reqIP)[0] == []byte(h.start)[0] { // if reqIP is in dynamic range
				if leaseNum := dhcp.IPRange(h.start, reqIP) - 1; leaseNum >= 0 && leaseNum < h.leaseRange { // allow if reqIP is in our range
					if l, exists := h.leases[leaseNum]; !exists || bytes.Equal(l.nic, p.CHAddr()) { // allow if reqIP doesn't exist yet or MAC is the same
						h.leases[leaseNum] = lease{nic: p.CHAddr(), expiry: time.Now().Add(h.leaseDuration)} // reserve the IP
						log.Printf("DHCPACK IP %v is granted for MAC %v\n", net.IP(options[dhcp.OptionRequestedIPAddress]).String(), p.CHAddr().String())
						return dhcp.ReplyPacket(p, dhcp.ACK, h.ip, net.IP(options[dhcp.OptionRequestedIPAddress]), h.leaseDuration,
							h.deniedOptions.SelectOrderOrAll(options[dhcp.OptionParameterRequestList]))
					}
				}
			} else {
				for _, v := range h.statics { // reqIP is not in dynamic range - search for static binding
					if v.ip.Equal(reqIP) && bytes.Equal(v.nic, p.CHAddr()) {
						log.Printf("DHCPACK Granting static IP Addr: %v to %v\n", reqIP.String(), p.CHAddr().String())
						return dhcp.ReplyPacket(p, dhcp.ACK, h.ip, net.IP(options[dhcp.OptionRequestedIPAddress]), h.leaseDuration,
							h.allowedOptions.SelectOrderOrAll(options[dhcp.OptionParameterRequestList]))
					}
				}
			}
		}
		log.Printf("DHCPNACK IP %v is NOT granted for MAC %v\n", net.IP(options[dhcp.OptionRequestedIPAddress]), p.CHAddr().String())
		return dhcp.ReplyPacket(p, dhcp.NAK, h.ip, nil, 0, nil)

	case dhcp.Release, dhcp.Decline:
		nic := p.CHAddr()
		for i, v := range h.leases {
			if bytes.Equal(v.nic, nic) {
				log.Printf("DHCPRELEASE Releasing address %v for MAC %v\n", i, nic)
				delete(h.leases, i)
				break
			}
		}

	case dhcp.Inform:
		log.Printf("DHCPINFORM from MAC %v and IP %v\n", p.CHAddr().String(), p.CIAddr().String())
	}
	return nil
}

func initializeStaticLeases() (map[int]staticlease, *gorp.DbMap) {
	configFile, err := os.Open("config.json")
	if err != nil {
		fmt.Println("opening config file", err.Error())
	}

	jsonParser := json.NewDecoder(configFile)
	if err = jsonParser.Decode(&settings); err != nil {
		fmt.Println("parsing config file", err.Error())
	}
	db, err := sql.Open("mymysql", settings.Database+"/"+settings.User+"/"+settings.Password)
	if err != nil {
		log.Fatal("Couldn't establish DB Connection!\n", err)
		return nil, nil
	}
	dbmap := &gorp.DbMap{Db: db, Dialect: gorp.MySQLDialect{"MyISAM", "UTF8"}}
	defer dbmap.Db.Close()
	dbmap.TraceOn("[gorp]", log.New(os.Stdout, "dhcpdorf:", log.Lmicroseconds))

	// fetch all rows
	var rows []userTable
	_, err = dbmap.Select(&rows, "SELECT `ID`, `Active`, `Net`, `MAC`, `IP`, `validto`, `Switch`, `Port` from user ORDER BY `Net`, `Room` DESC")
	if err != nil {
		log.Fatal("Couldn't Select All from table!\n", err)
		return nil, nil
	}
	var staticleases = make(map[int]staticlease, 500)

	for x, p := range rows {
		rows[x].Active = rows[x].Active && (p.Validto.Equal(time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC)) || !(p.Validto.Before(time.Now())))
		currentNic, err := net.ParseMAC(rows[x].Mac)
		if err != nil {
			log.Fatalf("Found MYSQL Entry with wrong MAC format! ID: %d", rows[x].Id)
		}

		if rows[x].Ip == 0 || rows[x].Mac == "00:00:00:00:00:00" {
			continue
		}
		log.Printf("Found static lease: %v -> %v", rows[x].Mac, net.IP{134, 130, byte(rows[x].Net), byte(rows[x].Ip)})

		staticleases[x] = staticlease{
			nic:    currentNic,
			expiry: time.Now().Add(time.Hour),
			ip:     net.IP{134, 130, byte(rows[x].Net), byte(rows[x].Ip)},
		}
	}
	return staticleases, dbmap
}

func (h *DHCPHandler) giveOutIP(p dhcp.Packet) (net.IP, dhcp.Options) {
	free := net.IP{0, 0, 0, 0}
	nic := p.CHAddr()

	for _, v := range h.statics {
		// Check for static binding
		if bytes.Equal(v.nic, nic) {
			free = v.ip
			log.Printf("DHCPOFFER static IP Addr: %v to %v\n", free.String(), p.CHAddr().String())
			return v.ip, h.allowedOptions
		}
	}

	if free.Equal(net.IP{0, 0, 0, 0}) {
		// Check for previous dynamic lease
		for i, v := range h.leases {
			if bytes.Equal(v.nic, nic) {
				free = dhcp.IPAdd(h.start, i)
				log.Printf("DHCPOFFER OLD IP Addr: %v to %v\n", free.String(), p.CHAddr().String())
				return free, h.deniedOptions
			}
		}
	}

	if free.Equal(net.IP{0, 0, 0, 0}) {
		// Create new dynamic lease for client
		free = h.freeLease()
	}
	if free.Equal(net.IP{0, 0, 0, 0}) {
		log.Fatalf("No more free IPs for host %v available :(\n", p.CHAddr().String())
		return nil, nil
	}
	log.Printf("DHCPOFFER NEW IP Addr: %v to %v\n", free.String(), p.CHAddr().String())
	return free, h.deniedOptions
}

func (h *DHCPHandler) freeLease() net.IP {
	now := time.Now()
	b := rand.Intn(h.leaseRange) // Try random first
	for _, v := range [][]int{[]int{b, h.leaseRange}, []int{0, b}} {
		for i := v[0]; i < v[1]; i++ {
			if l, ok := h.leases[i]; !ok || l.expiry.Before(now) {
				return dhcp.IPAdd(h.start, i)
			}
		}
	}
	return net.IP{0, 0, 0, 0}
}
