package plugin

import (
	"Yasso/config"
	"Yasso/config/banner"
	"Yasso/core/brute"
	"Yasso/core/logger"
	"Yasso/core/parse"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

var BurpMap = map[string]interface{}{
	"ssh":      SshConnByUser,
	"mongodb":  MongoAuth,
	"mysql":    MySQLConn,
	"mssql":    MssqlConn,
	"rdp":      RdpConn,
	"redis":    RedisAuthConn,
	"ftp":      FtpConn,
	"smb":      SmbConn,
	"winrm":    WinRMAuth,
	"postgres": PostgreConn,
}

func BruteService(user, pass string, ipd string, module string, thread int, timeout time.Duration, isAlive bool) {
	banner.Banner()
	defer func() {
		logger.Info("brute service complete")
	}()
	// First parse the IP list passed in
	if ipd == "" {
		logger.Fatal("need ips to parse")
		return
	}
	ips, err := parse.HandleIps(ipd)
	if err != nil {
		return
	}
	var userDic, passDic []string
	if user != "" {
		userDic, err = parse.ReadFile(user)
	}
	if pass != "" {
		passDic, err = parse.ReadFile(pass)
	}
	if err != nil {
		logger.Fatal("dic file is not found")
		return
	}
	var wg sync.WaitGroup
	var ipChannel = make(chan string, 1000)
	var ipAlive []string
	if isAlive == true {
		for i := 0; i < thread; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for ip := range ipChannel {
					if ping(ip) == true {
						logger.Info(fmt.Sprintf("%v is alive (ping)", ip))
						ipAlive = append(ipAlive, ip)
					}
				}
			}()
		}
		for _, ip := range ips {
			// IP addresses with ports will not be scanned, directly added
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

	logger.Info(fmt.Sprintf("start brute service %v", strings.Split(module, ",")))
	// Here we get the IP list, in various formats like www.baidu.com:80 192.168.248.1 192.168.248.1:445
	for _, each := range strings.Split(module, ",") { // Iterate through each service
		// Here we get the corresponding service and port
		service := strings.Split(each, ":")
		if len(service) >= 3 || len(service) <= 0 {
			logger.Fatal("brute service format is error")
			break
		}
		switch service[0] {
		case "ssh":
			var p int
			if len(service) == 2 {
				// With port, use the user-provided port
				p, err = strconv.Atoi(service[1])
			} else {
				// Without port, use the default
				p = 22
			}
			if err != nil {
				logger.Fatal("port number useless")
				break
			}
			run(ipAlive, p, userDic, passDic, timeout, thread, "ssh", BurpMap["ssh"])
		case "mongo":
			var p int
			if len(service) == 2 {
				// With port, use the user-provided port
				p, err = strconv.Atoi(service[1])
			} else {
				// Without port, use the default
				p = 27017
			}
			if err != nil {
				logger.Fatal("port number useless")
				break
			}
			run(ipAlive, p, userDic, passDic, timeout, thread, "mongodb", BurpMap["mongodb"])
		case "mysql":
			var p int
			if len(service) == 2 {
				// With port, use the user-provided port
				p, err = strconv.Atoi(service[1])
			} else {
				// Without port, use the default
				p = 3306
			}
			if err != nil {
				logger.Fatal("port number useless")
				break
			}
			run(ipAlive, p, userDic, passDic, timeout, thread, "mysql", BurpMap["mysql"])
		case "rdp":
			var p int
			if len(service) == 2 {
				// With port, use the user-provided port
				p, err = strconv.Atoi(service[1])
			} else {
				// Without port, use the default
				p = 3389
			}
			if err != nil {
				logger.Fatal("port number useless")
				break
			}
			run(ipAlive, p, userDic, passDic, timeout, thread, "rdp", BurpMap["rdp"])
		case "redis":
			var p int
			if len(service) == 2 {
				// With port, use the user-provided port
				p, err = strconv.Atoi(service[1])
			} else {
				// Without port, use the default
				p = 6379
			}
			if err != nil {
				logger.Fatal("port number useless")
				break
			}
			run(ipAlive, p, userDic, passDic, timeout, thread, "redis", BurpMap["redis"])
		case "smb":
			var p int
			if len(service) == 2 {
				// With port, use the user-provided port
				p, err = strconv.Atoi(service[1])
			} else {
				// Without port, use the default
				p = 445
			}
			if err != nil {
				logger.Fatal("port number useless")
				break
			}
			run(ipAlive, p, userDic, passDic, timeout, thread, "smb", BurpMap["smb"])
		case "winrm":
			var p int
			if len(service) == 2 {
				// With port, use the user-provided port
				p, err = strconv.Atoi(service[1])
			} else {
				// Without port, use the default
				p = 5985
			}
			if err != nil {
				logger.Fatal("port number useless")
				break
			}
			run(ipAlive, p, userDic, passDic, timeout, thread, "winrm", BurpMap["winrm"])
		case "postgres":
			var p int
			if len(service) == 2 {
				// With port, use the user-provided port
				p, err = strconv.Atoi(service[1])
			} else {
				// Without port, use the default
				p = 5432
			}
			if err != nil {
				logger.Fatal("port number useless")
				break
			}
			run(ipAlive, p, userDic, passDic, timeout, thread, "postgres", BurpMap["postgres"])
		case "mssql":
			var p int
			if len(service) == 2 {
				// With port, use the user-provided port
				p, err = strconv.Atoi(service[1])
			} else {
				// Without port, use the default
				p = 1433
			}
			if err != nil {
				logger.Fatal("port number useless")
				break
			}
			run(ipAlive, p, userDic, passDic, timeout, thread, "mssql", BurpMap["mssql"])
		case "ftp":
			var p int
			if len(service) == 2 {
				// With port, use the user-provided port
				p, err = strconv.Atoi(service[1])
			} else {
				// Without port, use the default
				p = 21
			}
			if err != nil {
				logger.Fatal("port number useless")
				break
			}
			run(ipAlive, p, userDic, passDic, timeout, thread, "ftp", BurpMap["ftp"])
		default:
			logger.Fatal(fmt.Sprintf("not found service %s", service[0]))
			return
		}
	}

}

// Execute the brute force function
func run(ips []string, port int, user, pass []string, timeout time.Duration, thread int, service string, method interface{}) {
	var ipChannel = make(chan string, 1000) // Reuse for the second time
	var mutex sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChannel {
				// Here we get each IP
				mutex.Lock()
				brute.NewBrute(user, pass, method, service, config.ServiceConn{
					Hostname: ip,
					Port:     port,
					Timeout:  time.Duration(timeout),
				}, thread, false, "").RunEnumeration()
				mutex.Unlock()
			}
		}()
	}
	for _, ip := range ips {
		// IP addresses with ports will not be scanned, skip directly
		if strings.Count(ip, ":") == 1 {
			if strings.Split(ip, ":")[1] == strconv.Itoa(port) { // With port, and the port is the same as the port to be brute forced
				ipChannel <- strings.Split(ip, ":")[0]
			} else {
				continue
			}
		} else {
			ipChannel <- ip
		}
	}
	close(ipChannel) // Prevent deadlock
	wg.Wait()
}
