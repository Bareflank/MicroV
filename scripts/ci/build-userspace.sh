PATH="/bin:$PATH"
mkdir ../build ../cache
cp scripts/cmake/config/config.cmake ..
echo 'set(ENABLE_BUILD_USERSPACE ON)' >> ../config.cmake
echo 'set(ENABLE_BUILD_VMM OFF)' >> ../config.cmake
cd ../build
cmake ../microv/deps/hypervisor -DCONFIG=../config.cmake
make
cp uvctl/x86_64-userspace-pe/build/uvctl.exe ../microv/
