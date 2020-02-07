package main

import (
	"bytes"
	"debug/macho"
	"errors"
	"os"
)

// MachoReader instance containing information
// about said binary
type MachoReader struct {
	ExecReader *macho.File
	File       *os.File
}

// NewMachoReader will create a new instance of MachoReader
func NewMachoReader(path string) (*MachoReader, error) {
	var r MachoReader
	var err error

	r.File, err = os.OpenFile(path, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil, errors.New("failed to open the file")
	}

	r.ExecReader, err = macho.NewFile(r.File)
	if err != nil {
		return nil, errors.New("failed to parse the Mach-O file succesfully")
	}

	return &r, nil
}

// ReaderParseSection will parse the section and
// return an array of bytes containing the content
// of the section, using the file instance..
func (r *MachoReader) ReaderParseSection(name string) []byte {
	var s *macho.Section
	if s = r.ExecReader.Section(name); s == nil {
		return nil
	}

	sectionSize := int64(s.Offset)

	_, err := r.File.Seek(0, 0)
	if err != nil {
		return nil
	}

	ret, err := r.File.Seek(sectionSize, 0)
	if ret != sectionSize || err != nil {
		return nil
	}

	buf := make([]byte, s.Size)
	if buf == nil {
		return nil
	}

	_, err = r.File.Read(buf)
	if err != nil {
		return nil
	}

	return buf
}

// ReaderParseStrings will parse the strings by a null terminator
// and then place them into an [offset => string] type map
// alignment does not matter here, as when \x00 exists more than once
// it will simply be skipped.
func (r *MachoReader) ReaderParseStrings(buf []byte) [][]byte {
	var slice [][]byte
	if slice = bytes.Split(buf, []byte("\x00")); slice == nil {
		return nil
	}

	return slice
}

// Close softly close all of the instances associated
// with the MachoReader
func (r *MachoReader) Close() {
	r.ExecReader.Close()
	r.File.Close()
}
