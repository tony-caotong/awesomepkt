# Command for fast begin.
sudo ./asmpkt -i lo \
	--ptype eth \
	--ptype ipv4 \
	--dst_mac 11:22:33:44:55:66 --src_mac 3e:d6:46:3c:5b:cc \
	--dst_ip 192.168.1.1 --src_ip 10.0.3.244 \
	--fix 30

# Note @ 2017-01-23
Mainly, it is just using to generate some test pkts for Tartaglia, so it maybe
pending it this version for a while.
