package parse

import (
	"Yasso/core/logger"
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/projectdiscovery/cdncheck"
)

// ReadFile Read data from a file
func ReadFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		logger.Fatal("open file has an error", err.Error())
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Split(bufio.ScanLines)
	var re []string
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		if text != "" {
			re = append(re, text)
		}
	}
	re = Duplicate(re) // Remove duplicates
	return re, nil
}

// ConvertDomainToIpAddress Convert domain names to IP addresses
func ConvertDomainToIpAddress(domains []string, thread int) ([]string, error) {
	checkChan := make(chan string, 100)
	var wg sync.WaitGroup
	var re []string
	for i := 0; i < thread; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range checkChan {
				if strings.Count(host, ".") == 3 && len(strings.Split(host, ":")) == 2 {
					// This is an IP address with a port
					re = append(re, host)
					continue
				}
				ip, err := net.LookupHost(host)
				if err != nil {
					continue
				}
				if ip != nil {
					// This proves there is a CDN, just drop it (don't scan domain names with CDN)
					if len(ip) >= 2 {
						logger.Info(fmt.Sprintf("%s has cdn %v", host, ip[:]))
						continue
					} else {
						for _, i := range ip {
							re = append(re, i)
						}
					}
				}
			}
		}()
	}
	for _, domain := range domains {
		if strings.Contains(domain, "http://") {
			domain = strings.TrimPrefix(domain, "http://")
		}
		if strings.Contains(domain, "https://") {
			domain = strings.TrimPrefix(domain, "https://")
		}
		checkChan <- domain
	}
	close(checkChan)
	wg.Wait()
	re = Duplicate(re) // Remove duplicates
	return re, nil
}

// cdnFilter CDN filter
func cdnFilter(ip string, client *cdncheck.Client) string {
	if found, _, err := client.Check(net.ParseIP(ip)); found && err == nil {
		return ip
	}
	return ""
}

// Duplicate Remove duplicates
func Duplicate(slc []string) []string {
	var re []string
	temp := map[string]byte{}
	for _, v := range slc {
		l := len(temp)
		temp[v] = 0
		if len(temp) != l {
			re = append(re, v)
		}
	}
	return re
}

// RegIpv4Address Match IPv4 addresses
func RegIpv4Address(context string) string {
	matched, err := regexp.MatchString("((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}", context)
	if err != nil {
		return ""
	}
	if matched {
		return context
	}
	return ""
}

func HandleIps(ip string) ([]string, error) {
	var Unprocessed []string
	var err error
	var basic []string

	if strings.Contains(ip, ".txt") {
		if strings.ToLower(path.Ext(filepath.Base(ip))) == ".txt" {
			// If the file extension is .txt, we parse the file and get the data results
			Unprocessed, err = ReadFile(ip)
			if err != nil {
				return []string{}, err
			}
		}
		/*
			The data format obtained here may be:
			192.168.248.1/24
			192.168.248.1-155
			www.baidu.com
			192.168.248.1:3389
			https://www.baidu.com
		*/

		// First wave of parsing begins, parsing IP address formats
		for _, i := range Unprocessed {
			switch {
			case RegIpv4Address(i) != "" && (strings.Count(i, "/24") == 1 || strings.Count(i, "/16") == 1):
				temp, err := ConvertIpFormatA(i)
				if err != nil {
					logger.Fatal("parse ip address has an error", err.Error())
					return []string{}, err
				}
				basic = append(basic, temp...)
			case RegIpv4Address(i) != "" && strings.Count(i, "-") == 1 && !strings.Contains(i, "/"):
				fmt.Println(i)
				temp, err := ConvertIpFormatB(i)
				if err != nil {
					logger.Fatal("parse ip address has an error", err.Error())
					return []string{}, err
				}
				basic = append(basic, temp...)
			case strings.Contains(i, "https://") || strings.Contains(i, "http://"):
				if strings.Contains(i, "https://") {
					basic = append(basic, strings.ReplaceAll(i, "https://", ""))
				}
				if strings.Contains(i, "http://") {
					basic = append(basic, strings.ReplaceAll(i, "https", ""))
				}
			default:
				basic = append(basic, i)
			}
		}
		// First wave of parsing complete, starting second wave of parsing for domain names
		basic = Duplicate(basic) // First deduplication
		basic, err = ConvertDomainToIpAddress(basic, 100)
		if err != nil {
			logger.Fatal("parse domain has an error", err.Error())
			return nil, err
		}
		basic = Duplicate(basic) // Second deduplication
	} else {
		basic, err = ConvertIpFormatAll(ip)
		if err != nil {
			logger.Fatal("parse ip address has an error", err.Error())
			return []string{}, err
		}
	}
	// Secondary filtering
	var newBasic []string
	for _, ip := range basic {
		if strings.Contains(ip, "/") {
			newBasic = append(newBasic, strings.Split(ip, "/")[0])
		} else {
			newBasic = append(newBasic, ip)
		}
	}
	// Sort the obtained IP addresses for subsequent operations
	sort.Strings(newBasic)
	return newBasic, err
}

// ConvertIpFormatA Currently does not parse 192.168.248.1/8 format
func ConvertIpFormatA(ip string) ([]string, error) {
	var ip4 = net.ParseIP(strings.Split(ip, "/")[0])
	if ip4 == nil {
		return []string{}, errors.New("not an ipv4 address")
	}
	var mark = strings.Split(ip, "/")[1]
	var temp []string
	var err error
	switch mark {
	case "24":
		var ip3 = strings.Join(strings.Split(ip[:], ".")[0:3], ".")
		for i := 0; i <= 255; i++ {
			temp = append(temp, ip3+"."+strconv.Itoa(i))
		}
		err = nil
	case "16":
		var ip2 = strings.Join(strings.Split(ip[:], ".")[0:2], ".")
		for i := 0; i <= 255; i++ {
			for j := 0; j <= 255; j++ {
				temp = append(temp, ip2+"."+strconv.Itoa(i)+"."+strconv.Itoa(j))
			}
		}
		err = nil
	default:
		temp = []string{}
		err = errors.New("not currently supported")
	}
	return temp, err
}

func ConvertIpFormatB(ip string) ([]string, error) {
	var ip4 = strings.Split(ip, "-")
	var ipA = net.ParseIP(ip4[0])
	if ip4 == nil {
		return []string{}, errors.New("not an ipv4 address")
	}
	var temp []string
	if len(ip4[1]) < 4 {
		iprange, err := strconv.Atoi(ip4[1])
		if ipA == nil || iprange > 255 || err != nil {
			return []string{}, errors.New("input format is not ccorrect")
		}
		var splitip = strings.Split(ip4[0], ".")
		ip1, err1 := strconv.Atoi(splitip[3])
		ip2, err2 := strconv.Atoi(ip4[1])
		prefixip := strings.Join(splitip[0:3], ".")
		if ip1 > ip2 || err1 != nil || err2 != nil {
			return []string{}, errors.New("input format is not ccorrect")
		}
		for i := ip1; i <= ip2; i++ {
			temp = append(temp, prefixip+"."+strconv.Itoa(i))
		}
	} else {
		var splitip1 = strings.Split(ip4[0], ".")
		var splitip2 = strings.Split(ip4[1], ".")
		if len(splitip1) != 4 || len(splitip2) != 4 {
			return []string{}, errors.New("input format is not ccorrect")
		}
		start, end := [4]int{}, [4]int{}
		for i := 0; i < 4; i++ {
			ip1, err1 := strconv.Atoi(splitip1[i])
			ip2, err2 := strconv.Atoi(splitip2[i])
			if ip1 > ip2 || err1 != nil || err2 != nil {
				return []string{}, errors.New("input format is not ccorrect")
			}
			start[i], end[i] = ip1, ip2
		}
		startNum := start[0]<<24 | start[1]<<16 | start[2]<<8 | start[3]
		endNum := end[0]<<24 | end[1]<<16 | end[2]<<8 | end[3]
		for num := startNum; num <= endNum; num++ {
			ip := strconv.Itoa((num>>24)&0xff) + "." + strconv.Itoa((num>>16)&0xff) + "." + strconv.Itoa((num>>8)&0xff) + "." + strconv.Itoa((num)&0xff)
			temp = append(temp, ip)
		}
	}
	return temp, nil
}

func ConvertIpFormatAll(ip string) ([]string, error) {
	reg := regexp.MustCompile(`[a-zA-Z]+`)
	switch {
	case strings.Count(ip, "/") == 1:
		return ConvertIpFormatA(ip)
	case strings.Count(ip, "-") == 1:
		return ConvertIpFormatB(ip)
	case reg.MatchString(ip):
		_, err := net.LookupHost(ip)
		if err != nil {
			return []string{}, err
		}
		return []string{ip}, nil
	default:
		var isip = net.ParseIP(ip)
		if isip == nil {
			return []string{}, errors.New("input format is not ccorrect")
		}
		return []string{ip}, nil
	}
}
