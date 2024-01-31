package credentials

import (
	"encoding/binary"
	"errors"
	"time"

	"github.com/Sireax/gokrb5/v8/types"
)

func (c *CCache) Marshal() ([]byte, error) {
	p := 0

	var data []byte

	//First byte of cache is always 5
	data = append(data, 5)
	p++

	// The second byte is file's version
	// For testing purposes I'll set it to 4
	data = append(data, 4)
	p++

	// On version 4 the byte order is BigEndian
	var endian binary.ByteOrder
	endian = binary.BigEndian

	// Writing header
	if c.Version == 4 {
		err := writeHeader(&data, &p, c, &endian)
		if err != nil {
			panic(err)
		}
	}

	// Writing principals
	err := writePrincipal(&data, &p, c, &endian, c.DefaultPrincipal)
	if err != nil {
		panic(err)
	}

	// Writing credentials
	for _, credential := range c.Credentials {
		err := writeCredential(&data, &p, c, &endian, credential)
		if err != nil {
			panic(err)
		}
	}

	return data, nil
}

func writeHeader(b *[]byte, p *int, c *CCache, e *binary.ByteOrder) error {
	//var err error

	if c.Version != 4 {
		return errors.New("Credentials cache version is not 4 so there is no header to parse.")
	}

	//First we write header's length
	writeInt16(b, p, e, int16(c.Header.length))

	for _, field := range c.Header.fields {
		writeInt16(b, p, e, int16(field.tag))
		writeInt16(b, p, e, int16(field.length))

		*b = append(*b, field.value...)
		//_, err = b.Write(field.value)
		//if err != nil {
		//	panic(err)
		//}
	}

	return nil
}

func writeInt16(b *[]byte, p *int, e *binary.ByteOrder, i int16) {
	buf := make([]byte, 2)
	switch *e {
	case binary.BigEndian:
		binary.BigEndian.PutUint16(buf, uint16(i))
	case binary.LittleEndian:
		binary.LittleEndian.PutUint16(buf, uint16(i))
	}
	*b = append(*b, buf...)
	*p += 2
}

func writeInt32(b *[]byte, p *int, e *binary.ByteOrder, i int32) {
	buf := make([]byte, 4)
	switch *e {
	case binary.BigEndian:
		binary.BigEndian.PutUint32(buf, uint32(i))
	case binary.LittleEndian:
		binary.LittleEndian.PutUint32(buf, uint32(i))
	}
	*b = append(*b, buf...)
	*p += 4
}

func writeInt8(b *[]byte, p *int, e *binary.ByteOrder, i int8) error {
	*b = append(*b, byte(i))
	*p++
	return nil
}

func writeCredential(b *[]byte, p *int, c *CCache, e *binary.ByteOrder, cred *Credential) error {
	var err error

	// Writing principals
	err = writePrincipal(b, p, c, e, cred.Client)
	if err != nil {
		panic(err)
	}
	err = writePrincipal(b, p, c, e, cred.Server)
	if err != nil {
		panic(err)
	}

	// Writing encryption key
	writeInt16(b, p, e, int16(cred.Key.KeyType))
	writeData(b, p, e, cred.Key.KeyValue)

	// Writing timestamps
	writeTimestamp(b, p, e, cred.AuthTime)
	writeTimestamp(b, p, e, cred.StartTime)
	writeTimestamp(b, p, e, cred.EndTime)
	writeTimestamp(b, p, e, cred.RenewTill)

	// Some key
	if cred.IsSKey {
		writeInt8(b, p, e, 1)
	} else {
		writeInt8(b, p, e, 0)
	}

	writeBytes(b, p, 4, e, cred.TicketFlags.Bytes)

	// Writing addresses
	l := len(cred.Addresses)
	writeInt32(b, p, e, int32(l))
	for _, a := range cred.Addresses {
		err = writeAddress(b, p, e, a)
		if err != nil {
			panic(err)
		}
	}

	// Writing auth data
	l = len(cred.AuthData)
	writeInt32(b, p, e, int32(l))
	for _, a := range cred.AuthData {
		err = writeAuthDataEntry(b, p, e, a)
		if err != nil {
			panic(err)
		}
	}

	// Writing tickets
	writeData(b, p, e, cred.Ticket)
	writeData(b, p, e, cred.SecondTicket)

	return err
}

func writePrincipal(b *[]byte, p *int, c *CCache, e *binary.ByteOrder, princ principal) error {
	var err error

	if c.Version != 1 {
		writeInt32(b, p, e, princ.PrincipalName.NameType)
	}
	nc := len(princ.PrincipalName.NameString)
	writeInt32(b, p, e, int32(nc))
	lenRealm := len(princ.Realm)
	writeInt32(b, p, e, int32(lenRealm))

	realmBytes := []byte(princ.Realm)
	*b = append(*b, realmBytes...)
	*p += len(realmBytes)

	for _, name := range princ.PrincipalName.NameString {
		writeInt32(b, p, e, int32(len(name)))
		*b = append(*b, []byte(name)...)
		*p += len(name)
	}

	return err
}

func writeAuthDataEntry(b *[]byte, p *int, e *binary.ByteOrder, a types.AuthorizationDataEntry) error {
	writeInt16(b, p, e, int16(a.ADType))
	writeData(b, p, e, a.ADData)
	return nil
}

func writeData(b *[]byte, p *int, e *binary.ByteOrder, data []byte) {
	l := len(data)
	writeInt32(b, p, e, int32(l))
	writeBytes(b, p, l, e, data)
}

func writeBytes(b *[]byte, p *int, s int, e *binary.ByteOrder, data []byte) {
	//switch *e {
	//case binary.BigEndian:
	//	err := binary.Write()
	//}
	*b = append(*b, data...)
	*p += s
}

func writeAddress(b *[]byte, p *int, e *binary.ByteOrder, a types.HostAddress) error {
	writeInt16(b, p, e, int16(a.AddrType))
	writeData(b, p, e, a.Address)
	return nil
}

func writeTimestamp(b *[]byte, p *int, e *binary.ByteOrder, t time.Time) error {
	writeInt32(b, p, e, int32(t.Unix()))
	return nil
}
