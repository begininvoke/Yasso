package spy

import (
	"Yasso/core/logger"
	"Yasso/pkg/netspy/icmp"
	"fmt"
	"sync"
	"sync/atomic"
)

func GoSpy(ips [][]string, check func(ip string) bool, thread int) []string { // Public function
	var online []string
	var wg sync.WaitGroup
	var ipc = make(chan []string, 10000)
	var onc = make(chan string, 1000)
	var count int32
	if ips == nil {
		return online
	}
	go func() {
		for _, ipg := range ips {
			ipc <- ipg
		}
		defer close(ipc)
	}()
	for i := 0; i < thread; i++ {
		wg.Add(1)
		go func(ipc chan []string) {
			for ipg := range ipc {
				for _, ip := range ipg {
					if icmp.Check(ip) {
						online = append(online, ip) // At this point, it can be proven that a network segment is alive
						logger.Info(fmt.Sprintf("%s/24 network segment to survive", ip))
						onc <- fmt.Sprintf("%s/24\n", ip)
						break // If one host exists, it proves it's alive
					} else {
						// Not alive
						continue
					}
				}
				atomic.AddInt32(&count, int32(len(ipg)))
			}
			defer wg.Done()
		}(ipc)
	}
	wg.Wait()
	return online
}
