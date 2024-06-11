# Install script for directory: /home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/Pcap++

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

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/Pcap++/libPcap++.a")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/pcapplusplus" TYPE FILE FILES
    "/home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/Pcap++/header/Device.h"
    "/home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/Pcap++/header/NetworkUtils.h"
    "/home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/Pcap++/header/PcapDevice.h"
    "/home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/Pcap++/header/PcapFileDevice.h"
    "/home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/Pcap++/header/PcapFilter.h"
    "/home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/Pcap++/header/PcapLiveDevice.h"
    "/home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/Pcap++/header/PcapLiveDeviceList.h"
    "/home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/Pcap++/header/RawSocketDevice.h"
    "/home/hun/Desktop/Anti_Virus/PcapPlusPlus-23.09/Pcap++/header/LinuxNicInformationSocket.h"
    )
endif()

