package logger

import (
	"Yasso/config"
	"encoding/csv"
	"fmt"
	"os"
	"strings"
)

var LogCSV string

// CSVSave saves data in CSV format
func CSVSave(host string, t int, in ...interface{}) {
	if LogCSV != "" {
		file, err := os.OpenFile(LogCSV, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			Fatal("Failed to open CSV file:", err.Error())
			return
		}
		defer file.Close()

		writer := csv.NewWriter(file)
		defer writer.Flush()

		// Write headers if file is empty
		stat, err := file.Stat()
		if err != nil {
			Fatal("Failed to get file stats:", err.Error())
			return
		}
		if stat.Size() == 0 {
			headers := []string{"Host", "Type", "Ports", "Service", "Username", "Password", "Vulnerability", "Information"}
			if err := writer.Write(headers); err != nil {
				Fatal("Failed to write CSV headers:", err.Error())
				return
			}
		}

		switch t {
		case VulnerabilitySave:
			// Find the host in JSONSave and write its data
			for _, v := range config.JSONSave {
				if v.Host == host {
					vuln := in[0].(string)
					record := []string{
						host,
						"Vulnerability",
						strings.Trim(strings.Join(strings.Fields(fmt.Sprint(v.Port)), ","), "[]"),
						"",
						"",
						"",
						vuln,
						"",
					}
					if err := writer.Write(record); err != nil {
						Fatal("Failed to write CSV record:", err.Error())
					}
				}
			}

		case PortSave:
			ports := in[0].([]int)
			record := []string{
				host,
				"Port",
				strings.Trim(strings.Join(strings.Fields(fmt.Sprint(ports)), ","), "[]"),
				"",
				"",
				"",
				"",
				"",
			}
			if err := writer.Write(record); err != nil {
				Fatal("Failed to write CSV record:", err.Error())
			}

		case WeakPassSave:
			serviceName := in[0].(string)
			credentials := in[1].(map[string]string)
			for username, password := range credentials {
				record := []string{
					host,
					"WeakPass",
					"",
					serviceName,
					username,
					password,
					"",
					"",
				}
				if err := writer.Write(record); err != nil {
					Fatal("Failed to write CSV record:", err.Error())
				}
			}

		case InformationSave:
			serviceName := in[0].(string)
			info := in[1].(string)
			record := []string{
				host,
				"Information",
				"",
				serviceName,
				"",
				"",
				"",
				info,
			}
			if err := writer.Write(record); err != nil {
				Fatal("Failed to write CSV record:", err.Error())
			}
		}
	}
}
