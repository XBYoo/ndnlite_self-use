           <local-port> <remote-ip> <remote-port> <name-prefix>

./consumer 5000 192.168.1.21 5001 /example/data
./producer 5000 192.168.1.21 5001 /example/data

./producer 5000 192.168.1.21 5001 /example/data
./producer 5000 192.168.1.21 5001 /example/data

  	<name-prefix> <port>=56363 <group-ip>=224.0.23.170
  	
 ./group_consumer /example/data 56363 224.0.23.170
 ./group_producer /example/data 56363 224.0.23.170
