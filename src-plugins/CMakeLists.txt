# add include directoy
include_directories(.)
include_directories(crypto)
include_directories(generic)
include_directories(nhdp)
include_directories(olsrv2)

# add subdirectories
#add_subdirectory(crypto)
add_subdirectory(generic)
add_subdirectory(nhdp)
add_subdirectory(olsrv2)
add_subdirectory(subsystems)
