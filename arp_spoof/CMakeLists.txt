# Require CMake version
CMAKE_MINIMUM_REQUIRED ( VERSION 3.1 )

# c++11
set (CMAKE_CXX_STANDARD 11)
set (CMAKE_CXX_STANDARD_REQUIRE ON)

# Project name
PROJECT ( "arp_spoof" )

# Executable file and source codes
SET ( OUTPUT_ELF
        "${CMAKE_PROJECT_NAME}"
        )
SET ( SRC_FILES
        src/main.cc
        src/arpspoof.cc
        src/session.cc
        )
 
# Header files (-I)
INCLUDE_DIRECTORIES ( include )
 
# Linking libraries (-l)
LINK_LIBRARIES( pcap )
LINK_LIBRARIES( pthread )
 
# Executable binary
ADD_EXECUTABLE( ${OUTPUT_ELF} ${SRC_FILES} )