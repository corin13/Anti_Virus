if(NOT EXISTS "/home/soyoung/Test2/PcapPlusPlus-23.09/install_manifest.txt")
  message(FATAL_ERROR "Cannot find install manifest: /home/soyoung/Test2/PcapPlusPlus-23.09/install_manifest.txt")
endif()

file(READ "/home/soyoung/Test2/PcapPlusPlus-23.09/install_manifest.txt" files)
string(REGEX REPLACE "\n" ";" files "${files}")
foreach(file ${files})
  message(STATUS "Uninstalling $ENV{DESTDIR}${file}")
  if(IS_SYMLINK "$ENV{DESTDIR}${file}" OR EXISTS "$ENV{DESTDIR}${file}")
    # If the file exists or is symlink
    # run remove command through cmake in command mode
    # See https://cmake.org/cmake/help/latest/manual/cmake.1.html#run-a-command-line-tool
    exec_program(
      "/usr/bin/cmake" ARGS "-E rm -rf \"$ENV{DESTDIR}${file}\""
      OUTPUT_VARIABLE rm_out
      RETURN_VALUE rm_retval
      )
    if(NOT "${rm_retval}" STREQUAL 0)
      message(FATAL_ERROR "Error when removing $ENV{DESTDIR}${file}")
    endif()
  else(IS_SYMLINK "$ENV{DESTDIR}${file}" OR EXISTS "$ENV{DESTDIR}${file}")
    message(STATUS "File $ENV{DESTDIR}${file} does not exist.")
  endif()
endforeach()
file(REMOVE "/home/soyoung/Test2/PcapPlusPlus-23.09/install_manifest.txt")
