"""
A script for ghidra to map the memory of ESP8266 in the correct way.
"""
import struct

SEGMENTS_DEFAULT_NAME = "Segment"
BOOTLOADER_SEGMENTS_NAME = "bootloader"

BOOTLOADER_START_ADDRESS = 0
FIRMWARE_START_ADDRESS = 0x1000


class ESP8266FirmwareMetaData(object):
    HEADER_LEN = 8
    HEADER_UNPACK_FORMAT = "<4BI"

    def __init__(self, fw_start_address, segments_name=SEGMENTS_DEFAULT_NAME):
        """
        Create object from the FW in the given address.
        :param int fw_start_address: the start of the firmware address.
        :param str segments_name: The name to give to the segments (the final name will be "<name><index>".
        """
        self.magic_char, \
        self.number_of_segments, \
        self.spi_flash_interface, \
        self.memory_info, \
        self.entry_point = \
            struct.unpack(self.HEADER_UNPACK_FORMAT, getBytes(toAddr(fw_start_address), self.HEADER_LEN))
        self.segments = []

        segment_start_addr = fw_start_address + self.HEADER_LEN
        for segment_index in range(self.number_of_segments):
            print(segment_start_addr)
            new_segment = MemorySegmentInfo.from_program(segments_name + str(segment_index), segment_start_addr)
            self.segments.append(new_segment)
            segment_start_addr += new_segment.size + MemorySegmentInfo.HEADER_LEN


class MemorySegmentInfo(object):
    HEADER_LEN = 8
    HEADER_UNPACK_FORMAT = "<II"

    def __init__(self, name, start_address, size, data_offset_in_binary):
        """
        Initialize the class with the needed values.
        :param str name: The name for the segment.
        :param int start_address: The start address of the segment.
        :param int size: The size of the segment.
        :param int data_offset_in_binary: The offset of the data in the binary.
        """
        self.name = name
        self.start_address = start_address
        self.size = size
        self.data_offset_in_binary = data_offset_in_binary

    @classmethod
    def from_program(cls, name, segment_start_address):
        """
        C'tor for the class from data in the FW using ghidra functions.
        :param str name: The name of the segment.
        :param int segment_start_address: The address of the segments in the FW.
        :return: Initialized instance.
        :rtype: MemorySegmentInfo
        """
        mapped_address, segment_size = struct.unpack(cls.HEADER_UNPACK_FORMAT,
                                                     getBytes(toAddr(segment_start_address), cls.HEADER_LEN))
        return cls(name, mapped_address, segment_size, segment_start_address)


def create_mapped_segments(segment_list):
    """
    Create mapped segments in the memory map for all segments in list.
    :param list of MemorySegmentInfo segment_list: The list of the segments to map.
    :return: Nothing
    """
    mem = currentProgram.getMemory()
    for segment_info in segment_list:
        mem.createByteMappedBlock(segment_info.name,
                                  toAddr(segment_info.start_address),
                                  toAddr(segment_info.data_offset_in_binary),
                                  segment_info.size)


def main():
    """
    Map all the segments in the recovered_file_update flash dump.
    """
    bootloader_meta_data = ESP8266FirmwareMetaData(BOOTLOADER_START_ADDRESS, BOOTLOADER_SEGMENTS_NAME)
    create_mapped_segments(bootloader_meta_data.segments)
    firmware_meta_data = ESP8266FirmwareMetaData(FIRMWARE_START_ADDRESS)
    create_mapped_segments(firmware_meta_data.segments)


if __name__ == '__main__':
    main()
