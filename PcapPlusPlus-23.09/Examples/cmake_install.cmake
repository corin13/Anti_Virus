# Install script for directory: /home/soyoung/Test2/PcapPlusPlus-23.09/Examples

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/home/soyoung/Test2/PcapPlusPlus-23.09/Examples/Arping/cmake_install.cmake")
  include("/home/soyoung/Test2/PcapPlusPlus-23.09/Examples/ArpSpoofing/cmake_install.cmake")
  include("/home/soyoung/Test2/PcapPlusPlus-23.09/Examples/DNSResolver/cmake_install.cmake")
  include("/home/soyoung/Test2/PcapPlusPlus-23.09/Examples/DnsSpoofing/cmake_install.cmake")
  include("/home/soyoung/Test2/PcapPlusPlus-23.09/Examples/HttpAnalyzer/cmake_install.cmake")
  include("/home/soyoung/Test2/PcapPlusPlus-23.09/Examples/IcmpFileTransfer/cmake_install.cmake")
  include("/home/soyoung/Test2/PcapPlusPlus-23.09/Examples/IPDefragUtil/cmake_install.cmake")
  include("/home/soyoung/Test2/PcapPlusPlus-23.09/Examples/IPFragUtil/cmake_install.cmake")
  include("/home/soyoung/Test2/PcapPlusPlus-23.09/Examples/PcapPlusPlus-benchmark/cmake_install.cmake")
  include("/home/soyoung/Test2/PcapPlusPlus-23.09/Examples/PcapPrinter/cmake_install.cmake")
  include("/home/soyoung/Test2/PcapPlusPlus-23.09/Examples/PcapSearch/cmake_install.cmake")
  include("/home/soyoung/Test2/PcapPlusPlus-23.09/Examples/PcapSplitter/cmake_install.cmake")
  include("/home/soyoung/Test2/PcapPlusPlus-23.09/Examples/SSLAnalyzer/cmake_install.cmake")
  include("/home/soyoung/Test2/PcapPlusPlus-23.09/Examples/TcpReassembly/cmake_install.cmake")
  include("/home/soyoung/Test2/PcapPlusPlus-23.09/Examples/TLSFingerprinting/cmake_install.cmake")

endif()

