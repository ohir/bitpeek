// Copyright 2018 OHIR-RIPE. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

package bitpeek

import (
	"fmt"
	"runtime"
	"testing"
)

// go test -run=Snap -coverprofile=mkcov.out
// go tool cover -html=mkcov.out
// GOMAXPROCS=1 go test -bench=. -benchmem | grep enchma | tee bench.txt; git commit -m 'new benchmark' bench.txt
// GOMAXPROCS=2 go test -bench=. -benchmem | grep enchma | tee bench.txt; git commit -m 'new benchmark' bench.txt
// GOMAXPROCS=4 go test -bench=. -benchmem | grep enchma | tee bench.txt; git commit -m 'new benchmark' bench.txt
// bullets ➊ ➋ ➌ ➍ ➎ ➏ ➐ ➑ ➒ ➓

// make this for Examples to compile
type EHeader uint16
type EXThead uint32

func (x EHeader) String() string { // make %s capable
	return string(Snap(
		`'PT:'F 'EXT=.ACK= Id:0xFHH`,
		uint64(x)))
}
func (x EXThead) String() string { // make %s capable
	return string(Snap(
		`'PT:'F 'EXT=.ACK= Id:0xFHH`,
		uint64(x)))
}
func (x EHeader) Verbose() string {
	return string(Snap(
		`Packet of F Type: 'Base Form,< Already ACKed,> 'Session ID: '0xFHH`,
		uint64(x)))
}
func (x EHeader) D(m string) { // make debug helper
	_, _, ln, _ := runtime.Caller(1) // ln that called D
	println(ln, "DBG >>", m, ">>", x.String())
}
func as(pic string) (r func(EHeader) []byte) {
	return func(x EHeader) []byte {
		return Snap(pic, uint64(x))
	}
}
func prettyHX(pic string) (r func(EXThead) []byte) {
	return func(x EXThead) []byte {
		return Snap(pic, uint64(x))
	}
}

// f**d tabs to align. Don't touch last three lines of Output template!

func ExampleSnap_allCommands() {
	// Show format commands in action:
	//
	var hdr uint64 = 0x7841AAbeefFDd37E
	fmt.Printf("%s\n", // use bitpeek.Snap, Luke!
		Snap(`'Show ALL'  ________________________________
'❶ Labels:' 'SYN=.ACK<.ERR>.EXT=  with  0 1 1 1  bits
'❷ Labels:' 'SYN=.ACK<.ERR>.EXT=  with  1 0 0 0  bits
          ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
' ‾‾‾‾‾‾‾‾ label chain: SYN=.ACK<.ERR>.EXT='
'  Char C:' C
' Label ?:' 'BitIs: ?
' Ascii A:' A
' Decimal:' D.08@	('D.08@')
'   Hex H:' 0xHH 	('0xHH')
' Octal  :' 0EFF 	('0EFF')
'  C32s G:' GG   	('GG')
' Three F:' F
'   Duo E:' E
'   Bit B:' B
'  Quoted:' '偩 =<\'>?ABCDEFGH\t_Tab\t_Tab\n NewLine: \\backslash ԹՖ'
' Escapes:' 偩 \=\<\'\>\?\A\B\C\D\E\F\G\H\t_Tab\t_Tab\n NewLine: \\backslash ԹՖ
`, hdr))

	// print hdr as flags, crc, address :port
	// I##.###.###.32@ picture is valid too for IPv4.
	fmt.Printf("%s\n\n%s\n",
		Snap(`(SYN= ACK= ERR= EXT= OVL= RTX= "GG") 'From: 'IPv4.Address32@:D.16@`, hdr),
		Snap(`--- Snap raCCCCCCD.16@ ns ---`, 0x6e20666f72200e0d))

	// Output:
	// Show ALL  ________________________________
	// ❶ Labels: syn.ERR.EXT  with  0 1 1 1  bits
	// ❷ Labels: SYN.ACK.ext  with  1 0 0 0  bits
	//           ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
	//  ‾‾‾‾‾‾‾‾ label chain: SYN=.ACK<.ERR>.EXT=
	//   Char C: A
	//  Label ?: BitIs: 1
	//  Ascii A: *
	//  Decimal: 190	(D.08@)
	//    Hex H: 0xEF 	(0xHH)
	//  Octal  : 0375 	(0EFF)
	//   C32s G: 2n   	(GG)
	//  Three F: 7
	//    Duo E: 3
	//    Bit B: 0
	//   Quoted: 偩 =<'>?ABCDEFGH	_Tab	_Tab
	//  NewLine: \backslash ԹՖ
	//  Escapes: 偩 =<'>?ABCDEFGH	_Tab	_Tab
	//  NewLine: \backslash ԹՖ
	//
	// (syn ACK ERR EXT OVL rtx "cb") From: 170.190.239.253:54142
	//
	// --- Snap ran for 3597 ns ---
}

// godoc bug: "@ bulb ` indicator" (`) gets code block distorted on the web

// Bitpeek lets you show a bit's state in six ways:
func ExampleSnap_indicators() {
	var pics = []struct {
		d string
		s string
	}{
		{`___input`, ` B  B  B  B`},        // B digit
		{`BulbsInd`, `' @=  @=  @=  @=`},   // @ bulb indicator
		{`BitDigit`, `'t? r? a? e?`},       // labeled version of B
		{`caMElize`, `'TX= RX= AK= ER=`},   // zero.ONE
		{`ShowOnes`, `'TX> RX> AK> ER>`},   // only if 1
		{`ShowZero`, `'TX< RX< AK< ER<\n`}, // only if 0
	}
	for _, n := range []uint64{11, 10, 5} {
		for _, v := range pics {
			fmt.Printf("%s: %s\n", v.d, Snap(v.s, n))
		}
	}
	// Output:
	// ___input:  1  0  1  1
	// BulbsInd:  @  `  @  @
	// BitDigit: t1 r0 a1 e1
	// caMElize: TX rx AK ER
	// ShowOnes: TX AK ER
	// ShowZero:  RX
	//
	// ___input:  1  0  1  0
	// BulbsInd:  @  `  @  `
	// BitDigit: t1 r0 a1 e0
	// caMElize: TX rx AK er
	// ShowOnes: TX AK
	// ShowZero:  RX ER
	//
	// ___input:  0  1  0  1
	// BulbsInd:  `  @  `  @
	// BitDigit: t0 r1 a0 e1
	// caMElize: tx RX ak ER
	// ShowOnes:  RX ER
	// ShowZero: TX AK
}

// Standard Command list shows D.dd@ picture giving decimal for numbers up to 16b.
// In fact Snap will cope with numbers up to 64b in length given proper pic.
// Below are generated pics for numbers in 17-64b range.
// Copy, paste & enjoy:
func ExampleSnap_decimals() {
	var fil string = `................`
	var spa string = `                  `
	var d, e, f, pf int
	fmt.Printf("D..17@")
	for e = 18; e < 65; e++ {
		d = e / 3
		f = d - 5
		if f > pf {
			fmt.Println("")
		} else {
			fmt.Printf("%s", spa[f:])
		}
		fmt.Printf("D%d%s%d@", e, fil[0:f], e)
		pf = f
	}

	// Output:
	// D..17@
	// D18.18@                 D19.19@                 D20.20@
	// D21..21@                D22..22@                D23..23@
	// D24...24@               D25...25@               D26...26@
	// D27....27@              D28....28@              D29....29@
	// D30.....30@             D31.....31@             D32.....32@
	// D33......33@            D34......34@            D35......35@
	// D36.......36@           D37.......37@           D38.......38@
	// D39........39@          D40........40@          D41........41@
	// D42.........42@         D43.........43@         D44.........44@
	// D45..........45@        D46..........46@        D47..........47@
	// D48...........48@       D49...........49@       D50...........50@
	// D51............51@      D52............52@      D53............53@
	// D54.............54@     D55.............55@     D56.............56@
	// D57..............57@    D58..............58@    D59..............59@
	// D60...............60@   D61...............61@   D62...............62@
	// D63................63@  D64................64@
}
func bigDecTestPictures() {
	var fil string = `...........................`
	var d, e, f int
	var n uint64
	fmt.Printf("{bigF, `Decimal big 17`, `D..17@`, `131071`, `bigdec`},\n")
	for e = 18; e < 65; e++ { // D..17@, D18.18@...
		d = e / 3
		f = d - 5
		n = 0xffffffffffffffff >> (64 - uint8(e))
		fmt.Printf("{bigF, `Decimal big %d`, `D%d%s%d@`, `%d`, `bigdec`},\n", e, e, fil[0:f], e, n)
	}
}
func ExampleSnap_typeMethods() {
	// // Define types:
	// type EHeader uint16
	//
	// // Add String() method for %s convenience:
	// func (x EHeader) String() string { // make %s capable
	// 	return string(bitpeek.Snap(
	// 		`'PT:'F 'EXT=.ACK= Id:0xFHH`,
	// 		uint64(x)))
	// }
	var ceh EHeader = 0xafdf

	// use String() method:
	fmt.Printf("_String: %s\n", ceh) // PT:5 ext.ACK Id:0x7DF

	// // Add Verbose() method for other form of output:
	// func (x EHeader) Verbose() string {
	// 	return string(bitpeek.Snap(
	//    `Packet of F Type: 'Base Form,< Already ACKed,> 'Session ID: '0xFHH`,
	// 		uint64(x)))
	// }

	fmt.Printf("Verbose: %s\n", ceh.Verbose())

	// // add a fancy STDERR debug helper:
	// func (x EHeader) D(m string) { // make debug helper
	// 	_, _, ln, _ := runtime.Caller(1) // ln that called D
	// 	println(ln, "DBG >>", m, ">>", x.String())
	// }
	//
	// // use D to print on STDERR:
	// ceh.D("Wasup!")
	// // 172 DBG >> Wasup! >> PT:5 ext.ACK Id:0x7DF

	// Output:
	// _String: PT:5 ext.ACK Id:0x7DF
	// Verbose: Packet of 5 Type: Base Form, Already ACKed, Session ID: 0x7DF
}

// If a single 'header type' has many forms (bluetooth anyone?) you may
// use a formatter factory and 'shape' tables:
func ExampleSnap_formatterFactory() {
	// // Make a formatter factory for EHeader
	// func as(pic string) (r func(EHeader) []byte) {
	// 	 return func(x EHeader) []byte {
	// 		 return bitpeek.Snap(pic, uint64(x))
	// 	 }
	// }
	notimp := as(`        Unknown packet type! (F!13@)`) // not all types are implemented
	var phPPs = []func(EHeader) []byte{
		as(`'Intaps: REP=.GRE=.SAB=.UMG=.DAG=.ERR= ml:A`), // pt(3b):rep:gre:sab:umg:dag:err:middleLetter
		as(`'CRCspe:' GG !02@'(Error detected!)>`),        // pt(3b):CRC(10b): : :err
		notimp,                                   // reserved
		notimp,                                   // reserved
		as(`'LinkUP:' for D.13@ seconds`),        // pt(3b):uptime(13b)
		as(`'  seen: PT:'F 'EXT=.ACK= Id:0xFHH`), // pt(3b):ext:ack:sessionid(11b)
		notimp,                                   // reserved
		as(`Status:' (Failure detected!)< oil:F gas:F ice:F spot:F`),
	}
	var tail EHeader = 0x15D7 // use same ending for all "packets"
	for i := 0; i < 8; i++ {
		v := tail | (EHeader(i) << 13)
		fmt.Printf("t%d :: %s\n", i, phPPs[v>>13](v))
	}
	// Output:
	// t0 :: Intaps: REP.gre.SAB.umg.DAG.ERR ml:W
	// t1 :: CRCspe: v2 (Error detected!)
	// t2 ::         Unknown packet type! (2)
	// t3 ::         Unknown packet type! (3)
	// t4 :: LinkUP: for 5591 seconds
	// t5 ::   seen: PT:5 EXT.ack Id:0x5D7
	// t6 ::         Unknown packet type! (6)
	// t7 :: Status: oil:2 gas:7 ice:2 spot:7
}

// There is a bug in fmt!
// fmt.Printf("PT:%d Ext:%1b Ack:%1b Id:0x%03X\n", x>>13, x>>12&1, x>>11&1, x&0x7FF)
// goes wild and prints:
// PT:5 Ext:0 Ack:1 Id:0x50543A30206578742E61636B2049643A3078374446

// It is possible to use Printf family to show bits albeit we're restricted
// to 'This:1' 'That:0' indicators. Not to mention poetry of bitshifts
// and masks that bugs love!
func ExampleSnap_bitpeekVsFmtPrintf() {
	// given packet spec:
	// |63|62|61| 60| 59|58|57|56|55|54|53|52|51|50|49|48| BIT
	// |GBU Type|ext|ack|           Session  Id          | HEADER
	// |47               Source Address H              33| IPv4
	// |32               Source Address L              16| IPv4
	// |15                 Source Port                  0| Port
	var packet uint64 = 0xafdfdeadbeef4d0e

	// Printf
	fmt.Printf("Type:%d Ext:%1d Ack:%1d Id:0x%03X from %d.%d.%d.%d:%d  :printf\n",
		// Are those shifts and masks valid?
		packet>>61, packet>>60&1, packet>>59&1, packet>>48&0x7FF,
		packet>>40&255, packet>>32&255, packet>>24&255, packet>>16&255, packet&0xffff)

	// Bitpeek
	fmt.Printf("%s  :bitpeek\n",
		Snap(`Type:'F 'Ext:? Ack:? Id:0xFHH from IPv4:Address32@:D.16@`, packet))

	// fmt.Sprintf    865 ns/op	   128 B/op	   9 allocs/op // returns string
	// bitpeek.Snap   280 ns/op	    64 B/op	   1 allocs/op // returns []byte

	// Output:
	// Type:5 Ext:0 Ack:1 Id:0x7DF from 222.173.190.239:19726  :printf
	// Type:5 Ext:0 Ack:1 Id:0x7DF from 222.173.190.239:19726  :bitpeek
}

const uAA = 0xaaaaaaaaaaaaaaaa
const u55 = 0x5555555555555555
const bigF = 0xffffffffffffffff

// testbed
var xparseTests = []struct {
	inp  uint64
	name string
	pic  string
	out  string
	desc string
}{
	{uAA, `B aa`, `pic`, `x`, ``},
	{u55, `B 55`, `pic`, `x`, ``},
}

var parseTests = []struct {
	inp  uint64
	name string
	pic  string
	out  string
	desc string
}{
	// simple commands
	{uAA, `B aa`, `BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB`,
		`1010101010101010101010101010101010101010101010101010101010101010`, `bits`},
	{u55, `B 55`, `BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB`,
		`0101010101010101010101010101010101010101010101010101010101010101`, `bits`},
	{uAA, `E aa`, `EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE`, `22222222222222222222222222222222`, `duos`},
	{u55, `E 55`, `EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE`, `11111111111111111111111111111111`, `duos`},
	{0, `E 00`, ` E`, ` 0`, `duos`},
	{3, `E 03`, ` E`, ` 3`, `duos`},
	{uAA, `F aa`, `FFFFFFFFFFFFFFFFFFFFF`, `252525252525252525252`, `tres`},
	{u55, `F 55`, `FFFFFFFFFFFFFFFFFFFFF`, `525252525252525252525`, `tres`},
	{0xFAC688, `F 7..0`, `FFFFFFFF`, `76543210`, `tres`},
	{uAA, `H aa`, `HHHHHHHHHHHHHHHH`, `AAAAAAAAAAAAAAAA`, `hex`},
	{u55, `H 55`, `HHHHHHHHHHHHHHHH`, `5555555555555555`, `hex`},
	{0xFEDCBA9876543210, `H F..0`, `HHHHHHHHHHHHHHHH`, `FEDCBA9876543210`, `hex`},
	{uAA, `A aa`, `AAAAAAAAA`, `*U*U*U*U*`, `ascii`},
	{u55, `A 55`, `AAAAAAAAA`, `U*U*U*U*U`, `ascii`},
	{0x21C30B1C4CB1B3C8, `A !..`, `AAAAAAAAA`, `!aBcDeFgH`, `ascii`},
	{uAA >> 3, `C aa>>3`, `CCCCCCCC`, `~UUUUUUU`, `char`},
	{u55, `C 55`, `CCCCCCCC`, `UUUUUUUU`, `char`},
	// unserved escapes
	{255, `Patho escape`, `\\A\\tB`, "\\A\\\t1", `patoesc`},
	// Labels
	{5, `Label no leading '`, `B3:? B2:? B1:? B0:?`, `B3:0 B2:1 B1:0 B0:1`, `label`},
	{5, `Label leading ?`, `?B3:? B2:? B1:? B0:?`, `0B3:0 B2:1 B1:0 B0:1`, `label`},
	{5, `Label leading =`, `=B3:? B2:? B1:? B0:?`, `B3:0 B2:1 B1:0 B0:1`, `label`},
	{5, `Label leading <`, `<B3:? B2:? B1:? B0:?`, `B3:0 B2:1 B1:0 B0:1`, `label`},
	{5, `Label leading >`, `>B3:? B2:? B1:? B0:?`, `B3:0 B2:1 B1:0 B0:1`, `label`},
	{5, `Label leading '=`, `'=B3:? B2:? B1:? B0:?`, `B3:0 B2:1 B1:0 B0:1`, `label`},
	{5, `Label leading '<`, `'<B3:? B2:? B1:? B0:?`, `B3:0 B2:1 B1:0 B0:1`, `label`},
	{5, `Label leading '>`, `'>B3:? B2:? B1:? B0:?`, `B3:0 B2:1 B1:0 B0:1`, `label`},
	{0x55, `Label @=`, `'@=@=@=@=@=@=@=@=`, "`@`@`@`@", `label`}, // R32emu bulblights
	{0xAA, `Label @=`, `'@=@=@=@=@=@=@=@=`, "@`@`@`@`", `label`},
	{0x5, `Label escapes`, `'d\?\<\'\>\=?c\?\<\'\>\=?b\?\<\'\>\=?a\?\<\'\>\=?`, `d?<'>=0c?<'>=1b?<'>=0a?<'>=1`, `label`},
	{0x5, `Label esc 2`, `'\?\<\'\>\=?\?\<\'\>\=?\?\<\'\>\=?\?\<\'\>\=?`, `?<'>=0?<'>=1?<'>=0?<'>=1`, `label`},
	{0x5, `Label esc 3`, `\?\<\'\>\=?\?\<\'\>\=?\?\<\'\>\=?\?\<\'\>\=?`, `?<'>=0?<'>=1?<'>=0?<'>=1`, `label`},
	{0x5, `Label noesc`, `ABCD@EFGH:\?|:\n?|:\t?|\':?`, "ABCD@EFGH:?|:\n1|:\t0|':1", `label`},
	{0x5, `Quoted  esc`, `ABCD@EFGH:\?|:\n?|:\t?|\':?'`, "ABCD@EFGH:?|:\n?|:\t?|':?", `label`},
	// mixing
	{0xFEDCBA9876543210, `Mix pic`,
		`L1? DRUS\E 'L2=L3<L4<L5<L6>L7>L8> HH '\t\nS'\n\t ZA`,
		"L11 DRUSE l2L4 64 \t\nS\n\t Z~", `mixing`},
	// bitskip
	{0x7D6142634465467B, `H }..{`, `CCCCCCCC`, `}aBcDeF{`, `bitskip`},
	{0x7D6142634465465e, `BitSkip`, `CCCCC!16@CC`, `~}aBcF^`, `bitskip`},
	{0x7D6142634465467B, `BitSkip zero`, `CCCC!00@CCCC`, `PICERR!DeF{`, `bitskip`},
	{0x7D6142634465465e, `BitSkip tail`, `CCCCCCCC!16@`, `~~}aBcDe`, `bitskip`},
	{1, `BitSkip err00`, `H!00@`, `CERR!`, `bitskip`},
	{1, `BitSkip err65`, `badH!65@`, `PICERR!`, `bitskip`},
	// Decimal
	{0, `Decimal  3b`, `D.03@`, `0`, `decimal`},
	{0xAA, `Decimal  0b`, `D.00@`, `CERR!`, `decimal`},
	{0xAA, `Decimal  3b`, `D.03@`, `2`, `decimal`},
	{0xAA, `Decimal  5b`, `D.05@`, `10`, `decimal`},
	{0xAA, `Decimal  7b`, `D.07@`, `42`, `decimal`},
	{0xAA, `Decimal  8b`, `D.08@`, `170`, `decimal`},
	{0xFade, `Decimal  9b`, `D.09@`, `222`, `decimal`},
	{0xFaed, `Decimal 11b`, `D.11@`, `749`, `decimal`},
	{0xFaed, `Decimal 13b`, `D.13@`, `6893`, `decimal`},
	{0xFaed, `Decimal 15b`, `D.15@`, `31469`, `decimal`},
	{0xBaFaed, `Decimal 16b`, `D.16@`, `64237`, `decimal`},
	{0xE, `Decimal 16b`, `D. 16@`, `ICERR!`, `decimal err`},
	{0xE, `Decimal 16b`, `D16@`, `ERR!`, `decimal err`},
	{0xAA, `Decimal 37 err`, `nothing to do D.37@`, `PICERR!`, `decimal`},
	{0xFEDCBA9876543210, `Decimal digit 00@`, `HHHHH!00@HHHHHHHHD.00@HH`, `PICERR!10`, `hex`},
	// more D digits. Rule is that Opening D need to be separated from .dd@ by
	// (floor(bits/3)-5) characters:
	{bigF, `Decimal big 17`, `D..17@`, `131071`, `bigdec`},
	{bigF, `Decimal big 18`, `D18.18@`, `262143`, `bigdec`},
	{bigF, `Decimal big 19`, `D19.19@`, `524287`, `bigdec`},
	{bigF, `Decimal big 20`, `D20.20@`, `1048575`, `bigdec`},
	{bigF, `Decimal big 21`, `D21..21@`, `2097151`, `bigdec`},
	{bigF, `Decimal big 22`, `D22..22@`, `4194303`, `bigdec`},
	{bigF, `Decimal big 23`, `D23..23@`, `8388607`, `bigdec`},
	{bigF, `Decimal big 24`, `D24...24@`, `16777215`, `bigdec`},
	{bigF, `Decimal big 25`, `D25...25@`, `33554431`, `bigdec`},
	{bigF, `Decimal big 26`, `D26...26@`, `67108863`, `bigdec`},
	{bigF, `Decimal big 27`, `D27....27@`, `134217727`, `bigdec`},
	{bigF, `Decimal big 28`, `D28....28@`, `268435455`, `bigdec`},
	{bigF, `Decimal big 29`, `D29....29@`, `536870911`, `bigdec`},
	{bigF, `Decimal big 30`, `D30.....30@`, `1073741823`, `bigdec`},
	{bigF, `Decimal big 31`, `D31.....31@`, `2147483647`, `bigdec`},
	{bigF, `Decimal big 32`, `D32.....32@`, `4294967295`, `bigdec`},
	{bigF, `Decimal big 33`, `D33......33@`, `8589934591`, `bigdec`},
	{bigF, `Decimal big 34`, `D34......34@`, `17179869183`, `bigdec`},
	{bigF, `Decimal big 35`, `D35......35@`, `34359738367`, `bigdec`},
	{bigF, `Decimal big 36`, `D36.......36@`, `68719476735`, `bigdec`},
	{bigF, `Decimal big 37`, `D37.......37@`, `137438953471`, `bigdec`},
	{bigF, `Decimal big 38`, `D38.......38@`, `274877906943`, `bigdec`},
	{bigF, `Decimal big 39`, `D39........39@`, `549755813887`, `bigdec`},
	{bigF, `Decimal big 40`, `D40........40@`, `1099511627775`, `bigdec`},
	{bigF, `Decimal big 41`, `D41........41@`, `2199023255551`, `bigdec`},
	{bigF, `Decimal big 42`, `D42.........42@`, `4398046511103`, `bigdec`},
	{bigF, `Decimal big 43`, `D43.........43@`, `8796093022207`, `bigdec`},
	{bigF, `Decimal big 44`, `D44.........44@`, `17592186044415`, `bigdec`},
	{bigF, `Decimal big 45`, `D45..........45@`, `35184372088831`, `bigdec`},
	{bigF, `Decimal big 46`, `D46..........46@`, `70368744177663`, `bigdec`},
	{bigF, `Decimal big 47`, `D47..........47@`, `140737488355327`, `bigdec`},
	{bigF, `Decimal big 48`, `D48...........48@`, `281474976710655`, `bigdec`},
	{bigF, `Decimal big 49`, `D49...........49@`, `562949953421311`, `bigdec`},
	{bigF, `Decimal big 50`, `D50...........50@`, `1125899906842623`, `bigdec`},
	{bigF, `Decimal big 51`, `D51............51@`, `2251799813685247`, `bigdec`},
	{bigF, `Decimal big 52`, `D52............52@`, `4503599627370495`, `bigdec`},
	{bigF, `Decimal big 53`, `D53............53@`, `9007199254740991`, `bigdec`},
	{bigF, `Decimal big 54`, `D54.............54@`, `18014398509481983`, `bigdec`},
	{bigF, `Decimal big 55`, `D55.............55@`, `36028797018963967`, `bigdec`},
	{bigF, `Decimal big 56`, `D56.............56@`, `72057594037927935`, `bigdec`},
	{bigF, `Decimal big 57`, `D57..............57@`, `144115188075855871`, `bigdec`},
	{bigF, `Decimal big 58`, `D58..............58@`, `288230376151711743`, `bigdec`},
	{bigF, `Decimal big 59`, `D59..............59@`, `576460752303423487`, `bigdec`},
	{bigF, `Decimal big 60`, `D60...............60@`, `1152921504606846975`, `bigdec`},
	{bigF, `Decimal big 61`, `D61...............61@`, `2305843009213693951`, `bigdec`},
	{bigF, `Decimal big 62`, `D62...............62@`, `4611686018427387903`, `bigdec`},
	{bigF, `Decimal big 63`, `D63................63@`, `9223372036854775807`, `bigdec`},
	{bigF, `Decimal big 64`, `D64................64@`, `18446744073709551615`, `bigdec`},
	// Ip address
	{0xdeadbeef, `IP v4 err`, `I##.###.###.##@`, `PICERR!`, `IP v4 err`},
	{0xdeadbeef, `IP v4 ok`, `I##.###.###.32@`, `222.173.190.239`, `IP v4 err`},
	//
	//	{0x5, `Label `, ``, `x`, `char`},
}

func TestSnap(t *testing.T) {
	fails := 0
	for _, v := range parseTests {
		o := string(Snap(v.pic, v.inp))
		if o != v.out {
			t.Logf("%s is broken! o≢e >%s< ≢ >%s<", v.name, o, v.out)
			fails++
		}
	}
	if fails != 0 {
		t.Logf("--- %d of %d tests failed! ---", fails, len(parseTests))
		t.Fail()
	}
}

func ConditionalLines() {
	pic := `
b1 is set>
b0 is unset<`

	// Conditional line-label:
	for i := uint64(0); i < 4; i++ {
		fmt.Printf("\n___ b1,b0: %02b ___%s", i,
			Snap(pic, i))
	}

	// Output:
	// 	___ b1,b0: 00 ___
	// b0 is unset
	// ___ b1,b0: 01 ___
	// ___ b1,b0: 10 ___
	// b1 is set
	// b0 is unset
	// ___ b1,b0: 11 ___
	// b1 is set
}

var header uint64 = 0xafdfdeadbeef4d0e

func BenchmarkSnapShort(b *testing.B) { // usual
	for i := 0; i < b.N; i++ {
		_ = Snap(`'PT:'F 'EXT=.ACK= Id:0xFHH!48@`, header)
	}
}
func BenchmarkSnapFixed(b *testing.B) { // usual
	for i := 0; i < b.N; i++ {
		_ = Snap(`'PT:'F 'EXT=.ACK= Id:0xFHH from HHHHHH:HH`, header)
	}
}
func BenchmarkSnapSlice(b *testing.B) { // usual
	for i := 0; i < b.N; i++ {
		_ = Snap(`'PT:'F 'EXT=.ACK= Id:0xFHH from IPv4:Address32@:D.16@`, header)
	}
}
func BenchmarkSnapString(b *testing.B) { // be fair to Sprintf
	for i := 0; i < b.N; i++ {
		_ = string(Snap(`'PT:'F 'Ext:? Ack:? Id:0xFHH from IPv4:Address32@:D.16@`, header))
	}
}
func BenchmarkSprintf(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = fmt.Sprintf("PT:%d Ext:%1d Ack:%1d Id:0x%03X from %d.%d.%d.%d:%d\n",
			header>>61, header>>60&1, header>>59&1, header>>48&0x7FF,
			header>>40&255, header>>32&255, header>>24&255, header>>16&255, header&0xffff)
	}
}
func BenchmarkSprintfHex64(b *testing.B) { // usual
	for i := 0; i < b.N; i++ {
		_ = fmt.Sprintf("%X", header)
	}
}
func BenchmarkSnapHex64(b *testing.B) { // usual
	for i := 0; i < b.N; i++ {
		_ = Snap(`HHHHHHHHHHHHHHHH`, header)
	}
}
func BenchmarkSnapHex32(b *testing.B) { // usual
	for i := 0; i < b.N; i++ {
		_ = Snap(`HHHHHHHH`, header)
	}
}
func BenchmarkSnapHex16(b *testing.B) { // usual
	for i := 0; i < b.N; i++ {
		_ = Snap(`HHHH`, header)
	}
}
func BenchmarkSnapHex12(b *testing.B) { // usual
	for i := 0; i < b.N; i++ {
		_ = Snap(`HHH`, header)
	}
}
func BenchmarkSnapHex8(b *testing.B) { // usual
	for i := 0; i < b.N; i++ {
		_ = Snap(`HH`, header)
	}
}
func BenchmarkErrorf(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = fmt.Errorf("PT:%d Ext:%1d Ack:%1d Id:0x%03X from %d.%d.%d.%d:%d\n",
			header>>61, header>>60&1, header>>59&1, header>>48&0x7FF,
			header>>40&255, header>>32&255, header>>24&255, header>>16&255, header&0xffff)
	}
}
func BenchmarkLong(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = Snap(`'Show ALL'  ________________________________
'❶ Labels:' 'SYN=.ACK<.ERR>.EXT=  with  0 1 1 1  bits
'❷ Labels:' 'SYN=.ACK<.ERR>.EXT=  with  1 0 0 0  bits
          ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾
' ‾‾‾‾‾‾‾‾ label chain: SYN=.ACK<.ERR>.EXT='
'  Char C:' C
' Label ?:' 'BitIs: ?
' Ascii A:' A
' Decimal:' D.08@	('D.08@')
'   Hex H:' 0xHH 	('0xHH')
' Octal  :' 0EFF 	('0EFF')
'  C32s G:' GG   	('GG')
' Three F:' F
'   Duo E:' E
'   Bit B:' B
'  Quoted:' '偩 =<\'>?ABCDEFGH\t_Tab\t_Tab\n NewLine: \\backslash ԹՖ'
' Escapes:' 偩 \=\<\'\>\?\A\B\C\D\E\F\G\H\t_Tab\t_Tab\n NewLine: \\backslash ԹՖ
`, header)
	}
}
