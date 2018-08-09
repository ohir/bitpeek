## Bitpeek. Human readable bits.

`import "github.com/ohir/bitpeek"`

### Overview

Bitpacked data pretty-formatter. Makes binary headers human readable.

Every single input bit from 0 to 63 can print a label that show this bit state.
Arbitrary group of bits can be printed as decimal, octal or hex numbers and as
C32s, Ascii7b or UTF8 characters. Plus as an IPv4 address in dot-notation.
Package has no dependencies and is faster than fmt.Sprintf used for identical output.


Taste it:

``` go
var header uint64 = 0xAfdfDeadBeef4d0e

println(string(bitpeek.Snap(
  `'Type:'F 'EXT=.ACK= Id:0xFHH from IPv4.Address32@:D.16@\n`,header)))
	
// Output:
// Type:5 ext.ACK Id:0x7DF from 222.173.190.239:19726
	
//   Benchmark:   277 ns/op  64 B/op 1 allocs/op (Sprintf: 862 ns/op)
```

### Easy Format String

	    (excerpt)	
	? - bitlabel with digit 0 or 1
	> - bitlabel - only if bit is SET
	< - bitlabel - only if bit is UNSET
	= - bitlabel lowercased if bit is UNSET  
	D - Decimal number
	H - Hex digit: 0..F
	C - Character (utf8)
	I - IPv4 address


### Documentation

[Documentation](http://godoc.org/github.com/ohir/bitpeek) is hosted at GoDoc project.


### Install

`go get -u github.com/ohir/bitpeek`


### TODO

* Picstring linter. Will be in github.com/ohir/bplint repo.
* Travis and coverage badges. 


### License

See LICENSE file (MIT).



