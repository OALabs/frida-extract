#!/usr/bin/env python
############################################################################################
##
## Rebuild PE file from dumped memory segments!
##
## All credit to @skier_t for original code: 
##      https://github.com/jbremer/godware/blob/master/rebuild.py
##      (Beers are on me if we ever meet again!)
##
## Hacks to make this a module: @herrcore  
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
    def __init__(self, sections, base_address=0x400000):
        """
            Manipulate memory sections to rebuild PE file
            sections: {<virtual_address> : [byte_1,byte_2 ... byte_n], <virtual_address> : [byte_1,byte_2 ... byte_n]}
        """
        self.base_address = base_address
        self.sections = sections


    def arr_to_bin(self, arr):
        """
            Convert array of int to binary string
        """
        out=''
        for i in arr:
            out += chr(i)
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
                    if image_section_header.Name.lower() != '.bss':
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


    def build_pe(self):
        """
            Construct PE from memory sections
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
            if image_section_header.Name.lower() == '.bss':
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
