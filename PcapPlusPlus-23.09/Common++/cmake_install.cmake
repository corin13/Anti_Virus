# Install script for directory: /home/choeun/Anti_Virus/PcapPlusPlus-23.09/Common++

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
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "/home/choeun/Anti_Virus/PcapPlusPlus-23.09/Common++/libCommon++.a")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/pcapplusplus" TYPE FILE FILES
    "/home/choeun/Anti_Virus/PcapPlusPlus-23.09/Common++/header/GeneralUtils.h"
    "/home/choeun/Anti_Virus/PcapPlusPlus-23.09/Common++/header/IpAddress.h"
    "/home/choeun/Anti_Virus/PcapPlusPlus-23.09/Common++/header/IpUtils.h"
    "/home/choeun/Anti_Virus/PcapPlusPlus-23.09/Common++/header/Logger.h"
    "/home/choeun/Anti_Virus/PcapPlusPlus-23.09/Common++/header/LRUList.h"
    "/home/choeun/Anti_Virus/PcapPlusPlus-23.09/Common++/header/MacAddress.h"
    "/home/choeun/Anti_Virus/PcapPlusPlus-23.09/Common++/header/OUILookup.h"
    "/home/choeun/Anti_Virus/PcapPlusPlus-23.09/Common++/header/PcapPlusPlusVersion.h"
    "/home/choeun/Anti_Virus/PcapPlusPlus-23.09/Common++/header/PointerVector.h"
    "/home/choeun/Anti_Virus/PcapPlusPlus-23.09/Common++/header/SystemUtils.h"
    "/home/choeun/Anti_Virus/PcapPlusPlus-23.09/Common++/header/TablePrinter.h"
    "/home/choeun/Anti_Virus/PcapPlusPlus-23.09/Common++/header/TimespecTimeval.h"
    )
endif()

