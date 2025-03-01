# Yasso
Powerful internal network penetration auxiliary tool set - Let Yasso be like the wind. Supports brute force attacks on services such as rdp, ssh, redis, postgres, mongodb, mssql, mysql, winrm, etc., fast port scanning, powerful web fingerprint recognition, and one-click exploitation of various built-in services (including fully interactive ssh login, mssql privilege escalation, redis one-click exploitation, mysql database query, winrm lateral movement, and multiple service exploits supporting socks5 proxy execution).

# New Features
Changed scanning and brute force methods on the original basis, removed unnecessary functions, and made the code more complete and clean.<br>
Added protocol recognition and port identification.
* The new version has not released a release version, please clone and compile it yourself.
# Features
```
Usage:
  Yasso [command]

Available Commands:
  all         Use all scanner module (.attention) Traffic is very big   
  completion  Generate the autocompletion script for the specified shell
  exploit     Exploits to attack the service
  help        Help about any command
  service     Detection or blasting services by module

Flags:
  -h, --help            help for Yasso
      --output string   set logger file (default "result.txt")
```

- all: One-click scanning function
- exploit: Common service exploitation (sqlserver, redis, ssh, Sunlogin, etc.)
- service: Service brute force and sub-scanning module

Please refer to -h for details
