package SecureBase

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"unicode/utf16"

	"github.com/beytullahakyuz/securebase-go/Keccak"
)

type SBEncoding int

const (
	UNICODE SBEncoding = iota
	UTF8
)

const defcharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!\"#&'()*,-.:;<>?@[]\\^_{}|~/+="
const base64standart = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

type SecureBase struct {
	globalcharset string
	padding       rune
	gencoding     SBEncoding
}

func NewSecureBase(encoding SBEncoding) *SecureBase {
	return &SecureBase{
		globalcharset: base64standart,
		padding:       '=',
		gencoding:     encoding,
	}
}

func NewSecureBaseWithKey(encoding SBEncoding, secretkey string) *SecureBase {
	sb := &SecureBase{
		gencoding: encoding,
	}
	sb.SetSecretKey(secretkey)
	return sb
}

func (sb *SecureBase) SetSecretKey(secretkey string) {
	if len(secretkey) != 0 {
		sb.globalcharset = defcharset
		sb.prSuffleCharset(secretkey)
		sb.padding = []rune(sb.globalcharset[64:])[0]
		sb.globalcharset = sb.globalcharset[:64]
	} else {
		sb.globalcharset = base64standart
		sb.padding = '='
	}
}

func (sb *SecureBase) Encode(input string) (string, error) {
	var bytes []byte
	var err error

	if sb.gencoding == UNICODE {
		bytes, err = sb.processEncoding(stringToUTF16LE(input))
		if err != nil {
			return "", err
		}
		return utf16LEToString(bytes), nil
	} else {
		bytes, err = sb.processEncoding([]byte(input))
		if err != nil {
			return "", err
		}
		return string(bytes), nil
	}
}

func (sb *SecureBase) Decode(input string) (string, error) {
	var result []byte
	var err error

	if sb.gencoding == UNICODE {
		result, err = sb.processDecoding(input)
		if err != nil {
			return "", err
		}
		return utf16LEToString(result), nil
	} else {
		result, err = sb.processDecoding(input)
		if err != nil {
			return "", err
		}
		return string(result), nil
	}
}

func (sb *SecureBase) processEncoding(input []byte) (result []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("Invalid data or secret key!")
			result = nil
		}
	}()
	baseArray := []rune(sb.globalcharset)
	pdata := input
	var encodedData []rune

	if len(pdata) > 0 {
		length := len(pdata)
		lengthDiv3 := length / 3
		remainder := length % 3
		encodedLength := (lengthDiv3 * 4) + map[bool]int{true: 0, false: 4}[remainder == 0]
		encodedData = make([]rune, encodedLength)
		dataIndex := 0
		encodedIndex := 0

		for i := 0; i < lengthDiv3; i++ {
			chunk := (int(pdata[dataIndex]) << 16) | (int(pdata[dataIndex+1]) << 8) | int(pdata[dataIndex+2])
			dataIndex += 3
			encodedData[encodedIndex] = baseArray[(chunk>>18)&63]
			encodedIndex++
			encodedData[encodedIndex] = baseArray[(chunk>>12)&63]
			encodedIndex++
			encodedData[encodedIndex] = baseArray[(chunk>>6)&63]
			encodedIndex++
			encodedData[encodedIndex] = baseArray[chunk&63]
			encodedIndex++
		}

		if remainder == 1 {
			lastByte := int(pdata[dataIndex])
			encodedData[encodedIndex] = baseArray[lastByte>>2]
			encodedIndex++
			encodedData[encodedIndex] = baseArray[((lastByte & 3) << 4)]
			encodedIndex++
			encodedData[encodedIndex] = sb.padding
			encodedIndex++
			encodedData[encodedIndex] = sb.padding
		} else if remainder == 2 {
			secondLastByte := int(pdata[dataIndex])
			dataIndex++
			lastByte := int(pdata[dataIndex])
			encodedData[encodedIndex] = baseArray[secondLastByte>>2]
			encodedIndex++
			encodedData[encodedIndex] = baseArray[((secondLastByte&3)<<4)|(lastByte>>4)]
			encodedIndex++
			encodedData[encodedIndex] = baseArray[(lastByte&15)<<2]
			encodedIndex++
			encodedData[encodedIndex] = sb.padding
		}
	}

	if sb.gencoding == UNICODE {
		return stringToUTF16LE(string(encodedData)), nil
	} else {
		return []byte(string(encodedData)), nil
	}
}

func (sb *SecureBase) processDecoding(input string) (result []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("Invalid data or secret key!")
			result = nil
		}
	}()
	baseArray := []rune(sb.globalcharset)
	var decodedData []byte

	if len(input) > 0 {
		base64Values := make(map[rune]byte)
		for i := 0; i < 64; i++ {
			base64Values[baseArray[i]] = byte(i)
		}

		length := len(input)
		paddingCount := 0
		if length > 0 && rune(input[length-1]) == sb.padding {
			paddingCount++
		}
		if length > 1 && rune(input[length-2]) == sb.padding {
			paddingCount++
		}

		decodedLength := (length*3)/4 - paddingCount
		decodedData = make([]byte, decodedLength)
		encodedIndex := 0
		decodedIndex := 0

		inputRunes := []rune(input)
		for encodedIndex < length {
			chunk := (int(base64Values[inputRunes[encodedIndex]]) << 18) |
				(int(base64Values[inputRunes[encodedIndex+1]]) << 12) |
				(int(base64Values[inputRunes[encodedIndex+2]]) << 6) |
				int(base64Values[inputRunes[encodedIndex+3]])
			encodedIndex += 4

			decodedData[decodedIndex] = byte((chunk >> 16) & 255)
			decodedIndex++

			if decodedIndex < decodedLength {
				decodedData[decodedIndex] = byte((chunk >> 8) & 255)
				decodedIndex++
			}

			if decodedIndex < decodedLength {
				decodedData[decodedIndex] = byte(chunk & 255)
				decodedIndex++
			}
		}
	}

	return decodedData, nil
}

func (sb *SecureBase) prSuffleCharset(secretkey string) {
	secrethash := computeHash(secretkey, 512)
	sb.globalcharset = fnSuffleCharset(sb.globalcharset, fnCharacterSetSecretKey(secrethash))
}

func computeHash(s string, key int) string {
	keccak := Keccak.New()
	input := []byte(s)

	hash, err := keccak.Hash(input, key)
	if err != nil {
		return ""
	}

	keccak.Dispose()

	hexString := ""
	for _, b := range hash {
		hexString += fmt.Sprintf("%02x", b)
	}

	return hexString
}

func fnSuffleCharset(data string, keys []int) string {
	characters := []rune(data)
	keylen := len(keys)
	for j := 0; j < keylen-1; j++ {
		for i := len(characters) - 1; i > 0; i-- {
			x := (i * keys[j]) % len(characters)
			temp := characters[i]
			characters[i] = characters[x]
			characters[x] = temp
		}
	}
	return string(characters)
}

func fnCharacterSetSecretKey(anahtar string) []int {
	arr := make([]int, len(anahtar))
	for i := 0; i < len(anahtar)-1; i++ {
		c := anahtar[i]
		hs := 0
		hs = (hs*31 + int(c)) % math.MaxInt32
		arr[i] = hs
	}
	return arr
}

func stringToUTF16LE(s string) []byte {
	runes := []rune(s)
	u16 := utf16.Encode(runes)
	buf := new(bytes.Buffer)
	for _, r := range u16 {
		binary.Write(buf, binary.LittleEndian, r)
	}
	return buf.Bytes()
}

func utf16LEToString(b []byte) string {
	u16s := make([]uint16, len(b)/2)
	for i := 0; i < len(u16s); i++ {
		u16s[i] = uint16(b[i*2]) + (uint16(b[i*2+1]) << 8)
	}
	return string(utf16.Decode(u16s))
}
