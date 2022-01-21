### QUIC-PING
A UDP client for sending "QUIC PING"s. 

### What is a QUIC PING?
A QUIC Initial packet with random payload and the version ```0xbabababa``` to force Version Negotiation.

### Usage
```
go build .
./QUIC-PING google.com:443 [--hexdump]

```
The option ```--hexdump``` saves the generated QUIC packet as hexdump to ```packet.txt```.
