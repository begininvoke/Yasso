package plugin

import (
	"Yasso/config"
	"Yasso/config/banner"
	"Yasso/core/brute"
	"Yasso/core/logger"
	"Yasso/core/parse"
	"Yasso/pkg/webscan"
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type scannerAll struct {
	ip        string        // IP list or file that needs to be parsed
	port      string        // Port list that needs to be parsed
	noAlive   bool          // Whether to detect alive hosts
	noBrute   bool          // Whether to perform brute force
	userPath  string        // Path to user dictionary needed for brute force
	passPath  string        // Path to password dictionary needed for brute force
	thread    int           // Number of threads needed for scanning
	timeout   time.Duration // Timeout for brute force
	noService bool          // Whether to detect services (including web)
	noVulcan  bool          // Whether to perform host-level vulnerability scanning
}

func NewAllScanner(ip, port string, isAlive, isBrute bool, user, pass string, thread int, timeout time.Duration, noService bool, noVulcan bool) *scannerAll {
	return &scannerAll{
		ip:        ip,
		port:      port,
		noAlive:   isAlive,
		noBrute:   isBrute,
		userPath:  user,
		passPath:  pass,
		thread:    thread,
		timeout:   timeout,
		noService: noService,
		noVulcan:  noVulcan,
	}
}

// RunEnumeration Execute the program
func (s *scannerAll) RunEnumeration() {
	banner.Banner()
	defer func() {
		logger.Info("Yasso scan complete")
	}()
	if s.ip == "" {
		logger.Fatal("need ips to parse")
		return
	}
	// 1. Parse the user's IP list
	ips, err := parse.HandleIps(s.ip)
	if err != nil {
		logger.Fatal("parse ips has an error", err.Error())
		return
	}
	// 2. Parse the user's port list
	var ports []int
	if s.port == "" {
		ports = config.DefaultScannerPort
	} else {
		ports, err = parse.HandlePorts(s.port)
		if err != nil {
			logger.Fatal("parse ports has an error", err.Error())
			return
		}
	}
	var user []string
	var pass []string
	// 3. Parse the user's dictionary, if there is no dictionary, use the default dictionary
	if s.userPath != "" {
		user, err = parse.ReadFile(s.userPath)
		if err != nil {
			logger.Fatal("parse user dict file has an error")
			return
		}
	}
	if s.passPath != "" {
		pass, err = parse.ReadFile(s.passPath)
		if err != nil {
			logger.Fatal("parse user dict file has an error")
			return
		}
		return
	} else {
		pass = config.PassDict
	}

	// 4. After parsing is complete, determine liveness through isAlive, using concurrent method
	var wg sync.WaitGroup
	var mutex sync.Mutex
	var ipChannel = make(chan string, 1000)
	var port7 []int = []int{139, 445, 135, 22, 23, 21, 3389}
	var ipAlive []string
	if s.noAlive == false {
		for i := 0; i < s.thread; i++ {
			wg.Add(1)
			go func(ctx context.Context) {
				defer wg.Done()
				for ip := range ipChannel {
					if ping(ip) == true {
						logger.Info(fmt.Sprintf("%v is alive (ping)", ip))
						logger.JSONSave(ip, logger.HostSave) // JSON storage
						ipAlive = append(ipAlive, ip)
					} else {
						// Here we try to detect 7 common ports, if one is open, it proves the IP is also in a live network segment
						for _, p := range port7 {
							if tcpConn(ip, p) == true {
								logger.Info(fmt.Sprintf("%v is alive (tcp)", ip))
								logger.JSONSave(ip, logger.HostSave) // JSON storage
								ipAlive = append(ipAlive, ip)
								break
							}
						}
					}
				}
			}(context.Background())
		}
		for _, ip := range ips {
			// IPs with ports are not scanned, directly added
			if strings.Contains(ip, ":") {
				ipAlive = append(ipAlive, ip)
				continue
			} else {
				ipChannel <- ip
			}
		}
		close(ipChannel) // Prevent deadlock
		wg.Wait()
	} else {
		ipAlive = ips
	}
	// 5. After scanning is complete, perform port scanning, also with high concurrency
	ipChannel = make(chan string, 1000) // Reuse
	var portAlive = make(map[string][]int)
	for i := 0; i < s.thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChannel {
				// Perform port scanning
				mutex.Lock()
				p := NewRunner(ports, ip, s.thread, tcpConn).RunEnumeration()
				portAlive[ip] = append(portAlive[ip], p...)
				logger.JSONSave(ip, logger.PortSave, p) // Store available ports
				mutex.Unlock()
			}
		}()
	}
	for _, ip := range ipAlive {
		// IPs with ports are not scanned, directly added
		if strings.Count(ip, ":") == 1 {
			t := strings.Split(ip, ":")
			p, err := strconv.Atoi(t[1])
			if err != nil {
				continue
			}
			portAlive[t[0]] = append(portAlive[t[0]], p)
			continue
		} else {
			ipChannel <- ip
		}
	}
	close(ipChannel) // Prevent deadlock
	wg.Wait()
	// 6. Port scanning ends, determine whether to perform brute force based on user instructions
	for k, v := range portAlive {
		// Examine each port of each IP to see which service it belongs to
		v = parse.RemoveDuplicate(v) // Remove duplicates
		sort.Ints(v)                 // Sort
		for _, p := range v {
			switch p {
			case 22:
				if s.noService == false {
					information := VersionSSH(config.ServiceConn{
						Hostname: k,
						Port:     p,
						Timeout:  s.timeout,
					})
					logger.JSONSave(k, logger.InformationSave, "ssh", information)
				}
				brute.NewBrute(user, pass, SshConnByUser, "ssh", config.ServiceConn{
					Hostname: k,
					Port:     p,
					Timeout:  s.timeout,
				}, s.thread, s.noBrute, "").RunEnumeration()
			case 21:
				// Unauthorized
				if ok, _ := FtpConn(config.ServiceConn{
					Hostname: k,
					Port:     p,
					Timeout:  s.timeout,
				}, "", ""); ok {
					continue
				}
				// Brute force FTP
				brute.NewBrute(user, pass, FtpConn, "ftp", config.ServiceConn{
					Hostname: k,
					Port:     p,
					Timeout:  s.timeout,
				}, s.thread, s.noBrute, "").RunEnumeration()
			case 445:
				// Unauthorized
				if ok, _ := SmbConn(config.ServiceConn{
					Hostname: k,
					Port:     p,
					Timeout:  s.timeout,
				}, "administrator", ""); ok {
					logger.Info(fmt.Sprintf("smb %s unauthorized", k))
					// Unauthorized, username and password are both null
					logger.JSONSave(k, logger.WeakPassSave, "smb", map[string]string{"null": "null"})
					continue
				}
				brute.NewBrute(user, pass, SmbConn, "smb", config.ServiceConn{
					Hostname: k,
					Port:     p,
					Timeout:  s.timeout,
				}, s.thread, s.noBrute, "").RunEnumeration()
			case 1433:
				if s.noService == false {
					ok, information := VersionMssql(config.ServiceConn{
						Hostname: k,
						Port:     p,
						Timeout:  s.timeout,
					})
					// If exists
					if ok {
						logger.JSONSave(k, logger.InformationSave, "mssql", information)
					}
				}
				brute.NewBrute(user, pass, MssqlConn, "mssql", config.ServiceConn{
					Hostname: k,
					Port:     p,
					Timeout:  s.timeout,
				}, s.thread, s.noBrute, "").RunEnumeration()
			case 2181:
				if s.noService == false {
					if ok, _ := ZookeeperConn(config.ServiceConn{
						Hostname: k,
						Port:     p,
						Timeout:  s.timeout,
					}, "", ""); ok {
						// Unauthorized
						logger.JSONSave(k, logger.WeakPassSave, "zookeeper", map[string]string{"null": "null"})
						continue
					}
				}
			case 3306:
				// Unauthorized
				if _, ok, _ := MySQLConn(config.ServiceConn{
					Hostname: k,
					Port:     p,
					Timeout:  s.timeout,
				}, "", ""); ok {
					logger.Info(fmt.Sprintf("mysql %s unauthorized", k))
					// Unauthorized, username and password are both null
					logger.JSONSave(k, logger.WeakPassSave, "mysql", map[string]string{"null": "null"})
					continue
				} else {
					brute.NewBrute(user, pass, MySQLConn, "mysql", config.ServiceConn{
						Hostname: k,
						Port:     p,
						Timeout:  s.timeout,
					}, s.thread, s.noBrute, "").RunEnumeration()
				}
			case 3389:
				// Only detect host version
				if s.noService == false {
					if ok, information := VersionRdp(config.ServiceConn{
						Hostname: k,
						Port:     p,
						Timeout:  s.timeout,
					}, "", ""); ok {
						// Version
						logger.JSONSave(k, logger.InformationSave, "rdp", information)
						continue
					}
				}
			case 6379:
				if s.noService == false {
					if _, ok, _ := RedisUnAuthConn(config.ServiceConn{
						Hostname: k,
						Port:     p,
						Timeout:  s.timeout,
					}, "", ""); ok {
						logger.JSONSave(k, logger.WeakPassSave, "redis", map[string]string{"null": "null"})
						continue
					}
				}
				brute.NewBrute(user, pass, RedisAuthConn, "redis", config.ServiceConn{
					Hostname: k,
					Port:     p,
					Timeout:  s.timeout,
				}, s.thread, s.noBrute, "").RunEnumeration()

			case 5432:
				brute.NewBrute(user, pass, PostgreConn, "postgres", config.ServiceConn{
					Hostname: k,
					Port:     p,
					Timeout:  s.timeout,
				}, s.thread, s.noBrute, "").RunEnumeration()
			case 5985:
				brute.NewBrute(user, pass, WinRMAuth, "winrm", config.ServiceConn{
					Hostname: k,
					Port:     p,
					Timeout:  s.timeout,
				}, s.thread, s.noBrute, "").RunEnumeration()
			case 11211:
				if s.noService == false {
					if ok, _ := MemcacheConn(config.ServiceConn{
						Hostname: k,
						Port:     p,
						Timeout:  s.timeout,
					}, "", ""); ok {
						logger.JSONSave(k, logger.WeakPassSave, "memcache", map[string]string{"null": "null"})
						continue
					}
				}
			case 27017:
				if s.noService == false {
					if ok, _ := MongoUnAuth(config.ServiceConn{
						Hostname: k,
						Port:     p,
						Timeout:  s.timeout,
					}, "", ""); ok {
						logger.JSONSave(k, logger.WeakPassSave, "mongodb", map[string]string{"null": "null"})
						break
					}
				}
				brute.NewBrute(user, pass, MongoAuth, "mongodb", config.ServiceConn{
					Hostname: k,
					Port:     p,
					Timeout:  s.timeout,
				}, s.thread, s.noBrute, "").RunEnumeration()
			default:
				if s.noService == false {
					webscan.DisMapConn(k, p, s.timeout)
				}
				continue
			}
		}
	}
	if s.noService == false {
		// 8. Perform Windows service scanning
		ipChannel = make(chan string, 1000) // Fourth reuse
		for i := 0; i < s.thread; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for ip := range ipChannel {
					mutex.Lock()
					func(ip string) {
						ok, information := NbnsScanConn(ip, 137, s.timeout)
						if ok {
							logger.JSONSave(ip, logger.InformationSave, "netbios", information)
						}
					}(ip)
					func(ip string) {
						ok, information := SmbScanConn(ip, 445, s.timeout)
						if ok {
							logger.JSONSave(ip, logger.InformationSave, "smb", information)
						}
					}(ip)
					func(ip string) {
						ok, information := OxidScanConn(ip, 135, s.timeout)
						if ok {
							logger.JSONSave(ip, logger.InformationSave, "oxid", information)
						}
						ok, information = DceRpcOSVersion(ip, 135, s.timeout)
						if ok {
							logger.JSONSave(ip, logger.InformationSave, "dcerpc", information)
						}
					}(ip)
					mutex.Unlock()
				}
			}()
		}
		for _, ip := range ipAlive {
			// IPs with ports are not scanned, directly added
			if strings.Count(ip, ":") == 1 && (strings.Split(ip, ":")[0] != strconv.Itoa(139) || strings.Split(ip, ":")[0] != strconv.Itoa(135) || strings.Split(ip, ":")[0] != strconv.Itoa(445)) {
				continue
			} else if strings.Split(ip, ":")[0] == strconv.Itoa(139) || strings.Split(ip, ":")[0] == strconv.Itoa(135) || strings.Split(ip, ":")[0] == strconv.Itoa(445) {
				ipChannel <- strings.Split(ip, ":")[0]
			} else {
				ipChannel <- ip
			}
		}
		close(ipChannel) // Prevent deadlock
		wg.Wait()        // Wait for completion

	}
	// 7. Perform host vulnerability scanning
	if s.noVulcan == false {
		ipChannel = make(chan string, 1000) // Fourth reuse
		for i := 0; i < s.thread; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for ip := range ipChannel {
					// Perform port scanning
					mutex.Lock()
					func() {
						ok := Ms17010Conn(config.ServiceConn{
							Hostname:  ip,
							Port:      445,
							Domain:    "",
							Timeout:   s.timeout,
							PublicKey: "",
						})
						if ok {
							logger.JSONSave(ip, logger.VulnerabilitySave, "MS17010")
						}
					}()
					func() {
						ok := SmbGhostConn(config.ServiceConn{
							Hostname:  ip,
							Port:      445,
							Domain:    "",
							Timeout:   s.timeout,
							PublicKey: "",
						})
						if ok {
							logger.JSONSave(ip, logger.VulnerabilitySave, "CVE-2020-0796")
						}
					}()
					mutex.Unlock()
				}
			}()
		}
		for _, ip := range ipAlive {
			// IPs with ports are not scanned, directly added
			if strings.Count(ip, ":") == 1 && strings.Split(ip, ":")[0] != strconv.Itoa(445) {
				continue
			} else if strings.Split(ip, ":")[0] == strconv.Itoa(445) {
				ipChannel <- strings.Split(ip, ":")[0]
			} else {
				ipChannel <- ip
			}
		}

		close(ipChannel) // Prevent deadlock
		wg.Wait()        // Wait for completion
	}
	logger.LoggerSave()
}
