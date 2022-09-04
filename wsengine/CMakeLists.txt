register_tap_files(wsengine-tap-register.c
    ${TSHARK_TAP_SRC}
)

set(wsengine_LIBS
    ui
    capchild
    caputils
    wiretap
    epan
    version_info
    wsutil
    ${APPLE_CORE_FOUNDATION_LIBRARY}
    ${APPLE_SYSTEM_CONFIGURATION_LIBRARY}
    ${WIN_WS2_32_LIBRARY}
    ${M_LIBRARIES}
)
set(wsengine_FILES
    $<TARGET_OBJECTS:capture_opts>
    $<TARGET_OBJECTS:cli_main>
    $<TARGET_OBJECTS:shark_common>
    wsengine-tap-register.c
    wsengine.c
    read_cmd.c
    dump_utils.c
    read_file.c
    write_file.c
    dump_filetypes.c
    dump_version.c
    dump_encaps.c
    ${TSHARK_TAP_SRC}
)

set_executable_resources(wsengine "WSEngine" UNIQUE_RC)
add_executable(wsengine ${wsengine_FILES})
set_extra_executable_properties(wsengine "Executables")
target_link_libraries(wsengine ${wsengine_LIBS})
executable_link_mingw_unicode(wsengine)
install(TARGETS wsengine RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
