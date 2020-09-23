all: pcap-test

pcap-test: main.c
	g++ -o pcap-test main.c -lpcap

clean:
	rm -f pcap-test
