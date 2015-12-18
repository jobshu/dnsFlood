# dnsFlood
C language LAN dns flooding tool that leverages RAW sockets. To use this program compile as follows:

  gcc -std=c11 dnsflood.c -o dnsFlood
  
and then run the output file as sudo, you are accessing RAW sockets!

 sudo ./dnsFlood interfaceName(eth0 or wlan0 for example)
