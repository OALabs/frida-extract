#!/usr/bin/env python
############################################################################################
##
## Rebuild PE file from dumped memory segments!
##
## All credit to @skier_t for original code: 
##      https://github.com/jbremer/godware/blob/master/rebuild.py
##      (Beers are on me if we ever meet again!)
##
## Hacks to make this a module and auto_build: @herrcore  
##
############################################################################################

__AUTHOR__ = '@herrcore'

import sys, struct
from ctypes import *

class IMAGE_DOS_HEADER(Structure):
    _fields_ = [
        ('e_magic', c_ushort),
        ('e_cblp', c_ushort),
        ('e_cp', c_ushort),
        ('e_crlc', c_ushort),
        ('e_cparhdr', c_ushort),
        ('e_minalloc', c_ushort),
        ('e_maxalloc', c_ushort),
        ('e_ss', c_ushort),
        ('e_sp', c_ushort),
        ('e_csum', c_ushort),
        ('e_ip', c_ushort),
        ('e_cs', c_ushort),
        ('e_lfarlc', c_ushort),
        ('e_ovno', c_ushort),
        ('e_res1', c_ushort * 4),
        ('e_oemid', c_ushort),
        ('e_oeminfo', c_ushort),
        ('e_res2', c_ushort * 10),
        ('e_lfanew', c_uint)
    ]

class IMAGE_FILE_HEADER(Structure):
    _fields_ = [
        ('Machine', c_ushort),
        ('NumberOfSections', c_ushort),
        ('TimeDateStamp', c_uint),
        ('PointerToSymbolTable', c_uint),
        ('NumberOfSymbols', c_uint),
        ('SizeOfOptionalHeader', c_ushort),
        ('Characteristics', c_ushort)
    ]

class IMAGE_DATA_DIRECTORY(Structure):
    _fields_ = [
        ('VirtualAddress', c_uint),
        ('Size', c_uint)
    ]

class IMAGE_OPTIONAL_HEADER(Structure):
    _fields_ = [
        ('Magic', c_ushort),
        ('MajorLinkerVersion', c_ubyte),
        ('MinorLinkerVersion', c_ubyte),
        ('SizeOfCode', c_uint),
        ('SizeOfInitializedData', c_uint),
        ('SizeOfUninitializedData', c_uint),
        ('AddressOfEntryPoint', c_uint),
        ('BaseOfCode', c_uint),
        ('BaseOfData', c_uint),
        ('ImageBase', c_uint),
        ('SectionAlignment', c_uint),
        ('FileAlignment', c_uint),
        ('MajorOperatingSystemVersion', c_short),
        ('MinorOperatingSystemVersion', c_short),
        ('MajorImageVersion', c_short),
        ('MinorImageVersion', c_short),
        ('MajorSubsystemVersion', c_short),
        ('MinorSubsystemVersion', c_short),
        ('Win32VersionValue', c_uint),
        ('SizeOfImage', c_uint),
        ('SizeOfHeaders', c_uint),
        ('CheckSum', c_uint),
        ('Subsystem', c_short),
        ('DllCharacteristics', c_short),
        ('SizeOfStackReserve', c_uint),
        ('SizeOfStackCommit', c_uint),
        ('SizeOfHeapReserve', c_uint),
        ('SizeOfHeapCommit', c_uint),
        ('LoaderFlags', c_uint),
        ('NumberOfRvaAndSizes', c_uint)
        # omit the DataDirectory
    ]

class IMAGE_NT_HEADERS(Structure):
    _fields_ = [
        ('Signature', c_uint),
        ('FileHeader', IMAGE_FILE_HEADER),
        ('OptionalHeader', IMAGE_OPTIONAL_HEADER)
    ]

IMAGE_SIZEOF_SHORT_NAME = 8

class IMAGE_SECTION_HEADER_Misc(Union):
    _fields_ = [
        ('PhysicalAddress', c_uint),
        ('VirtualSize', c_uint)
    ]

class IMAGE_SECTION_HEADER(Structure):
    _fields_ = [
        ('Name', c_char * IMAGE_SIZEOF_SHORT_NAME),
        ('Misc', IMAGE_SECTION_HEADER_Misc),
        ('VirtualAddress', c_uint),
        ('SizeOfRawData', c_uint),
        ('PointerToRawData', c_uint),
        ('PointerToRelocations', c_uint),
        ('PointerToLinenumbers', c_uint),
        ('NumberOfRelocations', c_short),
        ('NumberOfLinenumbers', c_short),
        ('Characteristics', c_uint)
    ]


class ParsePEError(Exception):
   pass


class ParsePE: 
    def __init__(self, sections, base_address=0x400000, verbose=False):
        """
            Manipulate memory sections to rebuild PE file
            sections: {<virtual_address> : [byte_1,byte_2 ... byte_n], <virtual_address> : [byte_1,byte_2 ... byte_n]}
        """
        self.base_address = base_address
        self.sections = sections
        self.verbose = verbose

    def _debug(self, msg):
        """
            Print debug messages 
        """
        if self.verbose:
            print msg

    def arr_to_bin(self, arr):
        """
            Convert array of int to binary string (sort of deserialize)
        """
        out=''
        for i in arr:
            out += chr(i)
        return out

    def dump_raw_sections(self):
        """
        Return array of sections
        """
        out = []
        for address in sorted(self.sections):
            temp_bin = self.arr_to_bin(self.sections[address])
            out.append(temp_bin)
        return out

    def dump_raw(self):
        """
        Sort sections by ascending address and return as binary blob
        """
        out = ''
        for address in sorted(self.sections):
            out += self.arr_to_bin(self.sections[address])
        return out


    def hunt_base_address(self):
        """
            Attempt to automatically identify (and set) base address based on the first PE header
            with matching sections in the memory segments.
            If no base address can be found the default 0x400000 is used.
        """
        candidates = []
        #find all candidates starting with PE magic bytes
        for address in self.sections.keys():
            if "MZ" == self.arr_to_bin(self.sections[address][:2]):
                candidates.append(address)

        #validate sections exist based on PE header of candidate
        for temp_base_address in candidates:
            try:
                header_data = self.arr_to_bin(self.sections[temp_base_address])
                # read the image dos header
                image_dos_header = IMAGE_DOS_HEADER.from_buffer_copy(header_data)
                # read the image nt headers
                image_nt_headers = IMAGE_NT_HEADERS.from_buffer_copy(header_data, image_dos_header.e_lfanew)

                bool_layout_match = True
                for x in xrange(image_nt_headers.FileHeader.NumberOfSections):
                    # read the image section header
                    image_section_header = IMAGE_SECTION_HEADER.from_buffer_copy(header_data, image_dos_header.e_lfanew + sizeof(c_uint) + sizeof(IMAGE_FILE_HEADER) + x * sizeof(IMAGE_SECTION_HEADER) + image_nt_headers.FileHeader.SizeOfOptionalHeader)

                    # find the memory for this section (skip .bss)
                    if (image_section_header.Name.lower() != '.bss') and (image_section_header.Name.lower() != 'bss'):
                        virtual_address = temp_base_address + image_section_header.VirtualAddress
                        if virtual_address not in self.sections.keys():
                            bool_layout_match = False
                #test if the layout matches
                if bool_layout_match:
                    self.base_address = temp_base_address
                    return True
            except:
                continue  
        return False

    def auto_build(self):
        """
            Attempt to automatically build a PE from memory segments.
            **WARNING: We assume the PE header is injected completely into one memory segment.
        """
        candidates = []

        #find all candidates starting with PE magic bytes
        for address in self.sections.keys():
            if "MZ" == self.arr_to_bin(self.sections[address][:2]):
                candidates.append(address)

        #attempt to build PE from each candidate
        for temp_base_address in candidates:
            self._debug("Testing candidate: " + hex(temp_base_address))
            out_file = ''
            try:
                header_data = self.arr_to_bin(self.sections[temp_base_address])
                # read the image dos header
                image_dos_header = IMAGE_DOS_HEADER.from_buffer_copy(header_data)
                # read the image nt headers
                image_nt_headers = IMAGE_NT_HEADERS.from_buffer_copy(header_data, image_dos_header.e_lfanew)

                image_size = image_nt_headers.OptionalHeader.SizeOfImage
                self._debug("Image Size: " + hex(image_size))

                ##################################################################
                # Build sections into contiguous binary block with base = 0x0.
                # This takes care of situations where the PE may be injected over
                # memory segment boundaries or all in one segment.
                # **may be memory-intensive**
                ##################################################################

                big_block = self.arr_to_bin(self.sections[temp_base_address])

                for ptr_address in sorted(self.sections):
                    #ignore segments below base
                    if ptr_address <= temp_base_address:
                        self._debug("Segment ignored: " + hex(ptr_address))
                        continue
                    #if segments are within range of PE images size append 
                    if ptr_address <= (temp_base_address + image_size):
                        self._debug("Append segment: " + hex(ptr_address))
                        #add padding if big_block hasn't reached ptr yet
                        padding = ptr_address - (len(big_block) + temp_base_address)
                        self._debug("Padding: " + hex(padding))
                        if padding < 0:
                            #something is wrong!
                            continue 
                        big_block += ('\x00' * padding) + self.arr_to_bin(self.sections[ptr_address])

                ##################################################################
                # Pick sections from memory block and convert from virtual 
                # addresses to PE physical addresses.
                ##################################################################

                #redundent but helps clairify we are now working on one contiguous block of memory
                image_dos_header = IMAGE_DOS_HEADER.from_buffer_copy(big_block)
                image_nt_headers = IMAGE_NT_HEADERS.from_buffer_copy(big_block, image_dos_header.e_lfanew)
                self._debug("Entry point: " + hex(image_nt_headers.OptionalHeader.AddressOfEntryPoint))
                self._debug("Image base: " + hex(image_nt_headers.OptionalHeader.ImageBase))

                #setup header based on offset of first section
                first_image_section_header = IMAGE_SECTION_HEADER.from_buffer_copy(big_block, image_dos_header.e_lfanew + sizeof(c_uint) + sizeof(IMAGE_FILE_HEADER) + image_nt_headers.FileHeader.SizeOfOptionalHeader)
                first_section_offset = first_image_section_header.PointerToRawData
                header_data = big_block[:first_section_offset]
                self._debug("Firt section offset: " + hex(first_section_offset))

                #add header to out buffer
                buf = header_data

                # enumerate each section
                for x in xrange(image_nt_headers.FileHeader.NumberOfSections):
                    # read the image section header
                    image_section_header = IMAGE_SECTION_HEADER.from_buffer_copy(header_data, image_dos_header.e_lfanew + sizeof(c_uint) + sizeof(IMAGE_FILE_HEADER) + x * sizeof(IMAGE_SECTION_HEADER) + image_nt_headers.FileHeader.SizeOfOptionalHeader)
                    self._debug(image_section_header.Name)
                    self._debug(hex(image_section_header.PointerToRawData))
                    self._debug(hex(image_section_header.VirtualAddress))
                    self._debug(hex(image_section_header.SizeOfRawData))

                    # ignore .bss sections
                    if (image_section_header.Name.lower() == '.bss') or (image_section_header.Name.lower() == 'bss'):
                        continue

                    # since base = 0x0 VirtualAddress is the offset in the memory segment
                    section_data = big_block[image_section_header.VirtualAddress:image_section_header.VirtualAddress+image_section_header.SizeOfRawData]
                    buf += section_data
                    
                return buf
            except Exception as e:
                continue
        return ''

    def build_pe(self):
        """
            Construct PE from memory sections
            This expects each memory section to contain one image section.
        """

        # find the section at the base address
        if self.base_address in self.sections.keys():
            header_data = self.arr_to_bin(self.sections[self.base_address])
        else:
            raise ParsePEError("No section found at the Base Address: " + hex(self.base_address))
            return ''

        # read the image dos header
        image_dos_header = IMAGE_DOS_HEADER.from_buffer_copy(header_data)

        # read the image nt headers
        image_nt_headers = IMAGE_NT_HEADERS.from_buffer_copy(header_data, image_dos_header.e_lfanew)

        # output buffer
        buf = header_data

        # enumerate each section
        for x in xrange(image_nt_headers.FileHeader.NumberOfSections):

            # read the image section header
            image_section_header = IMAGE_SECTION_HEADER.from_buffer_copy(header_data, image_dos_header.e_lfanew + sizeof(c_uint) + sizeof(IMAGE_FILE_HEADER) + x * sizeof(IMAGE_SECTION_HEADER) + image_nt_headers.FileHeader.SizeOfOptionalHeader)

            # find the memory for this section (skip .bss)
            if (image_section_header.Name.lower() == '.bss') or (image_section_header.Name.lower() == 'bss'):
                continue

            virtual_address = self.base_address + image_section_header.VirtualAddress

            if virtual_address not in self.sections.keys():
                raise ParsePEError("Can't find section " + image_section_header.Name + " at virtual address: " + hex(virtual_address))
                return ''

            #TODO: check the section size and make sure it matches, if no match then maybe concat next section
            data = self.arr_to_bin(self.sections[virtual_address])

            # prepend padding and append the data to the file
            buf += '\x00' * (image_section_header.PointerToRawData - len(buf))
            buf += data
            
        return buf
