package logger

import (
	"Yasso/config"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/gookit/color"
)

var (
	Cyan       = color.Cyan.Render
	Red        = color.Red.Render
	LightGreen = color.Style{color.Green, color.OpBold}.Render
	LightRed   = color.Style{color.Red, color.OpBold}.Render
)

const (
	PortSave          = 1
	HostSave          = 2
	WeakPassSave      = 3
	InformationSave   = 4
	VulnerabilitySave = 5
)

var LogFile string
var LogJson string
var mutex sync.Mutex

func Info(in ...interface{}) {
	mutex.Lock()
	var all []interface{}
	for k, v := range in {
		if k == len(in)-1 {
			all = append(all, fmt.Sprintf("%v", v))
		} else {
			all = append(all, fmt.Sprintf("%v ", v))
		}
	}
	fmt.Println(fmt.Sprintf("[%s] ", Cyan("*")) + fmt.Sprint(all...))

	file, err := os.OpenFile(LogFile, os.O_APPEND|os.O_CREATE|os.O_SYNC, 0666)
	if err != nil {
		Fatal("open file has an error", err.Error())
		return
	}
	defer file.Close()
	_, _ = file.WriteString(fmt.Sprintf("[*] " + fmt.Sprint(all...) + "\n"))
	mutex.Unlock()
}

func Success(in ...interface{}) {
	mutex.Lock()
	var all []interface{}
	for k, v := range in {
		if k == len(in)-1 {
			all = append(all, fmt.Sprintf("%v", v))
		} else {
			all = append(all, fmt.Sprintf("%v ", v))
		}
	}
	fmt.Println(fmt.Sprintf("[%s] ", LightGreen("+")) + fmt.Sprint(all...))

	file, err := os.OpenFile(LogFile, os.O_APPEND|os.O_CREATE|os.O_SYNC, 0666)
	if err != nil {
		Fatal("open file has an error", err.Error())
		return
	}
	defer file.Close()
	_, err = file.WriteString(fmt.Sprintf("[+] " + fmt.Sprint(all...) + "\n"))
	mutex.Unlock()
}

func Fatal(in ...interface{}) {
	var all []interface{}
	for k, v := range in {
		if k == len(in)-1 {
			all = append(all, fmt.Sprintf("%v", v))
		} else {
			all = append(all, fmt.Sprintf("%v ", v))
		}
	}
	fmt.Println(fmt.Sprintf("[%s] ", Red("#")) + fmt.Sprint(all...))
}

// JSONSave Save data in JSON format
func JSONSave(host string, t int, in ...interface{}) {
	if LogJson != "" {
		switch t {
		case VulnerabilitySave:
			for _, v := range config.JSONSave {
				// Service exists
				if v.Host == host {
					v.Vulnerability = append(v.Vulnerability, in[0].(string))
				}
			}
		case PortSave:
			// Port storage
			var flag = false
			for _, v := range config.JSONSave {
				// Service exists
				if v.Host == host {
					v.Port = in[0].([]int) // Store the port
					flag = true
				}
			}
			if flag == false {
				config.JSONSave = append(config.JSONSave, &config.Format{
					Host: host,
				})
				for _, v := range config.JSONSave {
					// Service exists
					if v.Host == host {
						v.Port = in[0].([]int) // Store the port
						flag = true
					}
				}
			}
		case HostSave:
			// Host storage
			config.JSONSave = append(config.JSONSave, &config.Format{
				Host: host,
			})
		case WeakPassSave:
			// Store service weak passwords in JSON
			for _, v := range config.JSONSave {
				// Service name already exists, add the password to its WeakPass
				// If the host was previously alive
				if v.Host == host {
					// Traverse the host's service list
					var flag = false
					for _, value := range v.Service {
						if value.Name == in[0].(string) { // Service name
							value.WeakPass = append(value.WeakPass, in[1].(map[string]string))
							flag = true // Indicates service exists
						}
					}
					// Host exists
					if flag == false {
						v.Service = append(v.Service, &config.Service{
							Name:     in[0].(string), // Service name
							WeakPass: []map[string]string{in[1].(map[string]string)},
						})
					}
					// Host exists
					if flag == false {
						v.Service = append(v.Service, &config.Service{
							Name:     in[0].(string), // Service name
							WeakPass: []map[string]string{in[1].(map[string]string)},
						})
					}
				}
			}
		case 4:
			// Information field
			for _, v := range config.JSONSave {
				// Service name already exists, add the password to its WeakPass
				// If the host was previously alive
				if v.Host == host {
					// Traverse the host's service list
					var flag = false
					for _, value := range v.Service {
						if value.Name == in[0].(string) { // Service name
							value.Information = append(value.Information, in[1].(string))
							flag = true // Indicates service exists
						}
					}
					// Host exists
					if flag == false {
						v.Service = append(v.Service, &config.Service{
							Name:        in[0].(string), // Service name
							Information: []string{in[1].(string)},
						})
					}
				}
			}
		}
		// Save in JSON format, the file will save the result set stored in the global variable
	}
}

func LoggerSave() {
	if LogJson != "" {
		body, err := json.Marshal(config.JSONSave)
		if err != nil {
			Fatal("save json marshal failed", err.Error())
			return
		}
		filePtr, err := os.Create(LogJson)
		if err != nil {
			fmt.Println("File creation failed", err.Error())
			return
		}
		defer filePtr.Close()
		// Create JSON encoder
		_, _ = filePtr.Write(body)
	}
}
