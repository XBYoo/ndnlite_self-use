#Usage: <local-port1> <remote-ip1> <remote-port1> <name-prefix1> 
#	<local-port2> <remote-ip2> <remote-port2> <name-prefix2>         v3
cd ..
cd build
./forwarder 2000 192.168.41.22 2010 /example/ndn 3000 192.168.1.21 3010 /example/ndn
