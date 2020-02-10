# Require CMake version
CMAKE_MINIMUM_REQUIRED ( VERSION 2.8 )
 
# Project name
PROJECT ( "send_arp" )

# Executable file and source codes
SET ( OUTPUT_ELF
        "${CMAKE_PROJECT_NAME}"
        )
SET ( SRC_FILES
        src/main.cpp
        src/arpspoof.cpp
        )
 
# Header files (-I)
INCLUDE_DIRECTORIES ( include )
 
# Linking libraries (-l)
LINK_LIBRARIES( pcap )
 
# Executable binary
ADD_EXECUTABLE( ${OUTPUT_ELF} ${SRC_FILES} )