// Copyright 2018 OHIR-RIPE. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Bitpacked data pretty-formatter. Makes bits human readable. Zero dependencies.
// Every single input bit from 0 to 63 can print a label that show this bit state.
// Arbitrary group of bits can be printed as decimal, octal or hex numbers and as
// C32s, Ascii7b or UTF8 characters. Plus as an IPv4 address in dot-notation.
// Taste it:
//     var header uint64 = 0xafdfdeadbeef4d0e
//
//     fmt.Printf("%s\n", bitpeek.Snap(
//       `'Type:'F 'EXT=.ACK= Id:0xFHH from IPv4.Address32@:D.16@`, header))
//
//     Output:
//     Type:5 ext.ACK Id:0x7DF from 222.173.190.239:19726
//
//     //   Benchmark:   277 ns/op  64 B/op 1 allocs/op (Sprintf: 862 ns/op)
//     // EscAnalysis: make([]byte, oi) escapes to heap
//
// Package has NO dependencies and its parser is under 170 LoC so it is useful
// where standard "fmt" and "log" packages are too heavy to use (ie. IoT, embed
// and high-throughput environments). Parser allocates heap memory only for
// its output. Pic (format) string is written in left-to-right order (most
// significant bit, b63 is on the left) so any shorter uint based type can be
// simply cast and fed to Snap function.
//
//    BITPEEK FORMAT STRING
//
//    QUOTES & LABELS
//         \ Escape : Next character is not interpreted except \n for
//                    NL, \t for TAB and \' for ' in quoted text.
//    'quoted text' : not interpreted. Exceptions given above.
//    'label*       : * means one of =<?> chars.  Labels can chain so
//                    only one opening '  is needed for the whole set.
//                    Eg. 'TX= ACK< ERR:? are three labels in a chain.
//                    Label can contain ESCAPED=<'>? chars. Otherwise
//                    its just quoted text due to opening '.
//    unquoted text : Unescaped ABCEFGH@<'>?= characters are commands.
//                    Escapes \n\t work, other chars are emitted asis.
//
//    COMMANDS
//         takes : emits                            (emits == outputs)
//    ? - 1 bit  : label with digit 0/1 in place of '?'
//    > - 1 bit  : label - only if bit is SET (1).    Otherwise skips.
//    < - 1 bit  : label - only if bit is UNSET (0).  Otherwise skips.
//    = - 1 bit  : label lowercased if bit is UNSET.  From  UC in pic.
//    B - 1 bit  : digit 0  1     : B for bit
//    E - 2 bits : digit 0..3     :
//    F - 3 bits : digit 0..7     :
//    H - 4 bits : hex digit 0..F : H for Hex
//    G - 5 bits : C32s character :              (CRC  spelling code)
//    A - 7 bits : 7b char/ascii; : A for Ascii  (emits ~ for A < 32)
//    C - 8 bits : 8b char/utf8;  : C for Char   (emits ~ for C < 32)
//    I -32 bits : IPv4 address   : Pic is IPv4.Address32@
//    D -dd bits : Decimal number : Pic is D.dd@           01< dd <16.
//    ! -dd bits : SKIP 'dd' bits : Pic is !dd@  (>>dd)    01< dd <63.
//    @          : dd@ (bitcount) : two digit number of bits to take.
//
package bitpeek

// Func Snap takes a string and an uint64 as input data. It returns byteslice
// filled with printable characters as directed by pic (format) string. Pic
// string represents b63 on its left and b0 on the right. Parser starts at b0
// so shorter ints can be simply cast.
//
// Notes
//
// ➊ Use !dd@ skips if you are interested only in bits on higher positions:
//     fmt.Printf("%s\n", bitpeek.Snap( // 48 to skip on the left of @.
//           `'Type:'F 'EXT=.ACK= Id:0xFHH!48@`, 0xafdfdeadbeef4d0e))
//
//     Output:
//     Type:5 ext.ACK Id:0x7DF
//
// ➋ UTF8 and ascii control characters (eg. NL) are passed as-is so you
// can make readable conditional "label-line":
//    bitpeek.Snap(`'
//    This line will show only if bit b1 is set>
//    This line will show only if bit b0 is unset<`,
//    header)
//
// ➌ It is possible to omit opening ' for a label at the start of
// the pic string:
//    pic := `' Label<` //
//    pic :=  ` Label<` // same effect as above
//
// ➍ H commands are grouped so \HHHH is a pic for 16b number in spite
// of escape (backslash) in front of first H. Use 'H'HHH if you really
// need literal H glued to the front of hex digits.
//
// ➎ \n\t escapes are always interpreted - even in a quoted text. There is
// no way to output literal `\n` or `\t`. Don't try.
//
func Snap(pic string, from uint64) []byte {
	pi := len(pic)         // pic index
	oi := pi               // output index
	var asis, c byte       // flow control, temp c
	ot := make([]byte, oi) //

ploop:
	for pi > 0 {
		pi--
		w := pic[pi]
		switch { // labels and escapes
		case pi > 0 && pic[pi-1] == '\\':
			switch w {
			case 'n':
				w = '\n'
			case 't':
				w = '\t'
			}
			oi--
			ot[oi] = w
			pi-- // skip leading \
			continue
		case asis == 0: // goto control
		case w == '\'':
			asis = 0
			continue
		case asis == 1: // '' emit quoted
			oi--
			ot[oi] = w
			continue
		case asis == 2: // lowercase label
			if w > 63 && w < 91 {
				w |= 0x20
			}
			fallthrough
		case asis == 3: // emit label.
			if w|3 == 63 {
				asis = 0
			} else {
				oi--
				ot[oi] = w
				continue
			}
		case asis == 4: // skip label
			if w|3 == 63 {
				asis = 0
			} else {
				continue
			}
		}
		switch w { // command
		case '\'': // 1: quoted
			asis = 1
			continue
		case '?': // labeled bit
			c = 48 + byte(from)&1
			asis = 3
			from >>= 1
		case 'B': // Bit
			c = 48 + byte(from)&1
			from >>= 1
		case 'H': // Hex, usually seen in flock
		shorth:
			c = byte(from) & 15
			if c < 10 {
				c += 0x30
			} else {
				c += 0x37
			}
			from >>= 4
			if pi > 0 && pic[pi-1] == 'H' {
				pi--
				oi--
				ot[oi] = c
				goto shorth
			}
		case 'C': // Character 8bit
			c = byte(from)
			if c < 32 {
				c = '~' // make printable
			}
			from >>= 8
		case 'A': // Ascii 7bit
			c = byte(from) & 0x7f
			if c < 32 {
				c = '~'
			}
			from >>= 7
		case '=': // lowercase if UNSET (0)
			asis = 2 + byte(from)&1 // 2: lower
			from >>= 1
		case '>': // emit label if SET (1)
			asis = 4 - byte(from)&1 // 3: emit
			from >>= 1
		case '<': // emit label if UNSET (0)
			asis = 3 + byte(from)&1 // 4: skip
			from >>= 1
		case 'F': // Three
			c = 48 + byte(from)&7
			from >>= 3
		case 'G': // emit C32s codes as Ascii
			c = byte(from) & 0x1f
			if c < 26 {
				c += 97 // 65 for C32S
			} else {
				c += 24
			}
			from >>= 5
		case 'E': // Duo
			c = 48 + byte(from)&3
			from >>= 2
		case '@': // skip, Dec, Internet bitcount @33!
			k := (10 * uint8(pic[pi-2]-48)) + uint8(pic[pi-1]-48)
			var d = 4
			if k > 16 {
				d = int(k / 3)
			}
			switch {
			case k == 0, k > 64:
				fallthrough
			default:
				e := `PICERR!`
				for i := 6; oi > 0 && i >= 0; i-- {
					oi--
					ot[oi] = e[i]
				}
				break ploop
			case pi > 2 && pic[pi-3] == '!': // !dd@ skip dd bits
				pi -= 3
				from >>= k
			case pi > d-1 && pic[pi-d] == 'D': // D.dd@ Decimal
				pi -= d
				v := from &^ (0xFFFFffffFFFFffff << k)
				from >>= k
				for v > 9 {
					k := v / 10
					oi--
					ot[oi] = byte(48 + v - k*10)
					v = k
				}
				oi--
				ot[oi] = byte(48 + v)
			case pi > 13 && pic[pi-14] == 'I': // I##.###.###.32@ Ip v4, 32bit
				pi -= 14
				for i := 0; i < 4; i++ {
					v := byte(from)
					from >>= 8
					for v > 9 {
						k := v / 10
						oi--
						ot[oi] = byte(48 + v - k*10)
						v = k
					}
					oi--
					ot[oi] = byte(48 + v)
					if i < 3 {
						oi--
						ot[oi] = '.'
					}
				}
			}
		default:
			c = w // as-is
		}
		if c != 0 {
			oi--
			ot[oi] = c
			c = 0
		}
	}
	if oi > 0 {
		return ot[oi:]
	}
	return ot
}
