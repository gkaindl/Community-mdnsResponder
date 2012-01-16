# Community mdnsResponder

…is an attempt to maintain patches against Apple's open-source mdnsResponder releases to make them work on POSIX-compatible systems. The repository contains a full fork of mdnsResponder, as well as patches against some vanilla releases from Apple.

At the moment, this README is mostly distilled from a couple of emails I wrote on bonjour-dev, and the patched targets will probably only compile/work on Linux.

## Build instructions

You need to have a gcc build environment installed. Additionally, make sure that GNU make, bison and flex are installed. 

	cd mDNSPosix
	make os=linux
	make install

## Additional info

The Apple-supplied package also includes init scripts to start mdnsd at boot time (mdnsd.sh).

## Registering on and browsing wide-area Bonjour

To register on a wide-area bonjour server, you'll also need a config file /etc/mdnsd.conf with contents

	hostname myhostname.myWABdomain.com
	zone myWABdomain.com
	secret-64 my-base64-encoded-secret-tsig-key
	secret-name my-secret-key-name

"secret-name" is optional: I added it because Apple's implementation automatically uses the domain name as the key name, while my DDNS server uses something different.

*NOTE: Ensure that there are NO extraneous whitespaces at the ends of the lines in /etc/mdnsd.conf -- If there are, it will not work.* 

You can also create a file /etc/mdnsd-services.conf, which can contain services that you want mdnsd to register when it is running. The format is exactly similar to the Services.txt file in mDNSPosix/ from Apple's tarball, since I basically just copied their code from mDNSResponder.c over to PosixDaemon.c. However, if you want to have a service registered both on the local and the wide-area domain, you'll need to include it twice, e.g. like

	my-ssh-service-name
	_ssh._tcp.
	22

	my-ssh-service-name
	_ssh._tcp. myWABdomain.com.
	22

NAT/PMP port forwarding will also work, if your router supports it (Apple-branded ones as well as some 3rd-party ones with custom firmware do).

*NOTE: Ensure that there are NO extraneous whitespaces at the ends of the lines in /etc/mdnsd-services.conf -- If there are, it will not work.* 

## Using dnsextd

In order to use dnsextd to run a wide-area Bonjour server, set up bind as described on http://dns-sd.org (I greatly recommend using an SQL DB as the zone storage).

Also, create a configuration file for dnsextd at /etc/dnsextd.conf of the following form (assuming that bind is running on port 5030).

	options {
		listen-on		port 53 {};
		nameserver		address 127.0.0.1 port 5030;
		private			port 5533;
		llq				port 5352;
	};

	zone "myWABdomain.com." {
		type public;
		allow-update { key "my-secret-key-name"; };
	};

	key "my-secret-key-name" {
		secret "my-secret-tsig-key";
	};

Replace my-secret-key-name with your TSIG key name, and my-secret-tsig-key with the actual TSIG key in base64 encoding. Keep the quotes!

Finally, verify that wide-area Bonjour is working by monitoring bind's syslog messages after adding your wide-area Bonjour settings under System Preferences -> Sharing -> Computer Name (Edit) -> Use dynamic global hostname on a MacOS X system.
