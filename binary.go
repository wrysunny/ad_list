package websocket_proxy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

func (p *ProxyType) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer

	// Set Len to Payload length (adjust if Len means total size).
	p.Len = uint16(len(p.Payload))

	// Write fixed fields in order.
	if err := binary.Write(&buf, binary.BigEndian, p.Type); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, p.Len); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, p.Src.Address); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, p.Src.Port); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, p.Dest.Address); err != nil {
		return nil, err
	}
	if err := binary.Write(&buf, binary.BigEndian, p.Dest.Port); err != nil {
		return nil, err
	}

	// Write variable Payload.
	if _, err := buf.Write(p.Payload); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (p *ProxyType) UnmarshalBinary(data []byte) error {
	buf := bytes.NewReader(data)

	// Read fixed fields in order.
	if err := binary.Read(buf, binary.BigEndian, &p.Type); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &p.Len); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &p.Src.Address); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &p.Src.Port); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &p.Dest.Address); err != nil {
		return err
	}
	if err := binary.Read(buf, binary.BigEndian, &p.Dest.Port); err != nil {
		return err
	}

	// Read variable Payload based on Len.
	p.Payload = make([]byte, p.Len)
	if _, err := io.ReadFull(buf, p.Payload); err != nil {
		return err
	}

	// Optional: Check if all data was consumed.
	if buf.Len() != 0 {
		return fmt.Errorf("extra data after parsing")
	}

	return nil
}
