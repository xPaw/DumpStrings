package main

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"os"
	"unicode"
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

	r.File, err = os.Open(path)
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

func (r *FileReader) PrintSections() {
	sectionNames := r.GetAllSectionNames()
	for _, name := range sectionNames {
		fmt.Println(name)
	}
}

// GetAllSectionNames returns all section names from the binary
func (r *FileReader) GetAllSectionNames() []string {
	var sectionNames []string

	switch r.FileType {
	case "elf":
		for _, s := range r.ExecReader.(*elf.File).Sections {
			sectionNames = append(sectionNames, s.Name)
		}
	case "pe":
		for _, s := range r.ExecReader.(*pe.File).Sections {
			sectionNames = append(sectionNames, s.Name)
		}
	case "macho":
		for _, s := range r.ExecReader.(*macho.File).Sections {
			sectionNames = append(sectionNames, s.Name)
		}
	}

	return sectionNames
}

// ReaderParseSection parses the section and returns an array of bytes containing the content
func (r *FileReader) ReaderParseSection(name string) []byte {
	switch r.FileType {
	case "elf":
		if s := r.ExecReader.(*elf.File).Section(name); s != nil {
			data, err := s.Data()
			if err == nil {
				return data
			}
		}
	case "pe":
		if s := r.ExecReader.(*pe.File).Section(name); s != nil {
			data, err := s.Data()
			if err == nil {
				return data
			}
		}
	case "macho":
		if s := r.ExecReader.(*macho.File).Section(name); s != nil {
			data, err := s.Data()
			if err == nil {
				return data
			}
		}
	}

	return nil
}

// ReaderParseStrings splits the byte buffer into slices, treating non-ASCII characters as delimiters.
func (r *FileReader) ReaderParseStrings(buf []byte) [][]byte {
	var result [][]byte
	var start int

	for i := 0; i < len(buf); i++ {
		// Check if the current byte is an ASCII character
		if buf[i] == 0 || buf[i] > 127 || !(unicode.IsPrint(rune(buf[i])) || unicode.IsSpace(rune(buf[i]))) {
			// If the current byte is non-ASCII, split here
			if start < i {
				result = append(result, buf[start:i])
			}
			start = i + 1
		}
	}

	// Add the last segment if there's any remaining data
	if start < len(buf) {
		result = append(result, buf[start:])
	}

	return result
}

// Close softly closes all of the instances associated with the FileReader
func (r *FileReader) Close() {
	r.ExecReader.Close()
	r.File.Close()
}
