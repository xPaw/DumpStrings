package main

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"os"
)

// ExecReader interface for common operations across different executable formats
type ExecReader interface {
	Close() error
}

// FileReader struct containing information about the binary
type FileReader struct {
	ExecReader ExecReader
	File       *os.File
	FileType   string
}

// NewFileReader creates a new instance of FileReader
func NewFileReader(path string, fileType string) (*FileReader, error) {
	var r FileReader
	var err error

	r.File, err = os.OpenFile(path, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return nil, err
	}

	r.FileType = fileType

	switch fileType {
	case "elf":
		r.ExecReader, err = elf.NewFile(r.File)
	case "pe":
		r.ExecReader, err = pe.NewFile(r.File)
	case "macho":
		r.ExecReader, err = macho.NewFile(r.File)
	default:
		r.File.Close()
		return nil, fmt.Errorf("unsupported file type: %s", fileType)
	}

	if err != nil {
		r.File.Close()
		return nil, err
	}

	return &r, nil
}

// ReaderParseSection parses the section and returns an array of bytes containing the content
func (r *FileReader) ReaderParseSection(name string) []byte {
	var sectionData []byte
	var sectionOffset int64
	var sectionSize uint64

	switch r.FileType {
	case "elf":
		if s := r.ExecReader.(*elf.File).Section(name); s != nil {
			sectionOffset = int64(s.Offset)
			sectionSize = s.Size
		}
	case "pe":
		if s := r.ExecReader.(*pe.File).Section(name); s != nil {
			sectionOffset = int64(s.Offset)
			sectionSize = uint64(s.Size)
		}
	case "macho":
		if s := r.ExecReader.(*macho.File).Section(name); s != nil {
			sectionOffset = int64(s.Offset)
			sectionSize = uint64(s.Size)
		}
	default:
		return nil
	}

	if sectionSize == 0 {
		return nil
	}

	_, err := r.File.Seek(0, 0)
	if err != nil {
		return nil
	}

	ret, err := r.File.Seek(sectionOffset, 0)
	if ret != sectionOffset || err != nil {
		return nil
	}

	sectionData = make([]byte, sectionSize)
	if sectionData == nil {
		return nil
	}

	_, err = r.File.Read(sectionData)
	if err != nil {
		return nil
	}

	return sectionData
}

// ReaderParseStrings parses the strings by a null terminator
func (r *FileReader) ReaderParseStrings(buf []byte) [][]byte {
	slice := bytes.Split(buf, []byte("\x00"))
	if slice == nil {
		return nil
	}
	return slice
}

// Close softly closes all of the instances associated with the FileReader
func (r *FileReader) Close() {
	r.ExecReader.Close()
	r.File.Close()
}
