### QUIC-PING
A UDP client for sending "QUIC PING"s. 

### What is a QUIC PING?
A QUIC Initial packet with random payload and the version ```0xbabababa``` to force Version Negotiation.

The QUIC PING packet satifies the minimum Initial datagram size (as specified in [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html#initial-size)), i.e. the unencrypted QUIC packet (header + payload) has a size of exactly 1200 bytes.

### Usage
```
go mod init quicping
go get golang.org/x/crypto/hkdf
go build .
./quicping google.com:443 [--hexdump]

```
The option ```--hexdump``` saves the generated QUIC packet as hexdump to ```packet.txt```.
