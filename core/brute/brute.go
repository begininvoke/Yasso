package brute

import (
	"Yasso/config"
	"Yasso/core/logger"
	"fmt"
	"math"
	"reflect"
	"strings"
	"sync"
)

type Brute struct {
	user        []string           // Username to be enumerated
	pass        []string           // Password to be enumerated
	bruteMethod interface{}        // Enumeration method
	service     string             // Service command
	serviceConn config.ServiceConn // Service connection
	thread      int                // Number of threads for brute force
	output      string             // Result output path
	noBrute     bool               // Whether to execute brute force
}

func NewBrute(user, pass []string, method interface{}, service string, serviceConn config.ServiceConn, thread int, noBrute bool, output string) *Brute {
	return &Brute{
		user:        user,
		pass:        pass,
		bruteMethod: method,
		output:      output,
		service:     service,
		thread:      thread,
		serviceConn: serviceConn,
		noBrute:     noBrute,
	}
}

// RunEnumeration Start brute force enumeration
func (b *Brute) RunEnumeration() {
	if b.noBrute == false {
		var wg sync.WaitGroup
		if len(b.user) == 0 {
			b.user = config.UserDict[b.service] // Get the user list for the corresponding port
		}
		if len(b.pass) == 0 {
			b.pass = config.PassDict
		}
		var t int
		if len(b.pass) <= b.thread {
			t = len(b.pass)
		} else {
			t = b.thread
		}
		// Split passwords
		num := int(math.Ceil(float64(len(b.pass)) / float64(b.thread))) // Number of users per goroutine
		// Split usernames
		all := map[int][]string{}
		for i := 1; i <= t; i++ {
			for j := 0; j < num; j++ {
				tmp := (i-1)*num + j
				if tmp < len(b.pass) {
					all[i] = append(all[i], b.pass[tmp])
				}
			}
		}
		for i := 1; i <= t; i++ {
			wg.Add(1)
			tmp := all[i]
			go func(tmp []string) {
				defer wg.Done()
				for _, p := range tmp {
					for _, u := range b.user {
						// Start brute force, service with username and password
						if strings.Contains(p, "{user}") {
							p = strings.ReplaceAll(p, "{user}", u)
						}
						if b.export(b.call(b.serviceConn, u, p), b.serviceConn.Hostname, b.serviceConn.Port, b.service, u, p, b.output) {
							return
						}
					}
				}
			}(tmp)
		}
		wg.Wait()
	}
}

// call Function call, brute force will call this module to perform operations
func (b *Brute) call(params ...interface{}) []reflect.Value {
	f := reflect.ValueOf(b.bruteMethod)
	if len(params) != f.Type().NumIn() {
		logger.Fatal(fmt.Sprintf("call func %v has an error", b.bruteMethod))
		return nil
	}
	args := make([]reflect.Value, len(params))
	for k, param := range params {
		if param == "" || param == 0 {
			continue
		}
		args[k] = reflect.ValueOf(param)
	}
	return f.Call(args)
}

// Result verification
func (b *Brute) export(v []reflect.Value, host string, port int, service, user, pass string, output string) bool {
	var mutex sync.Mutex
	for _, value := range v {
		switch value.Kind() {
		case reflect.Bool:
			if value.Bool() == true {
				mutex.Lock()
				logger.Success(fmt.Sprintf("brute %v:%v success [%v:%v][%v]", host, port, user, pass, service))
				logger.JSONSave(host, logger.WeakPassSave, service, map[string]string{user: pass})
				mutex.Unlock()
				return true
			}
		}
	}
	return false
}
