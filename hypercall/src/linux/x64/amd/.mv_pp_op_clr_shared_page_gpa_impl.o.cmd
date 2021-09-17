cmd_/home/user/working/microv/shim/linux/../../hypercall/src/linux/x64/amd/mv_pp_op_clr_shared_page_gpa_impl.o := gcc -Wp,-MD,/home/user/working/microv/shim/linux/../../hypercall/src/linux/x64/amd/.mv_pp_op_clr_shared_page_gpa_impl.o.d  -nostdinc -isystem /usr/lib/gcc/x86_64-linux-gnu/9/include  -I./arch/x86/include -I./arch/x86/include/generated  -I./include -I./arch/x86/include/uapi -I./arch/x86/include/generated/uapi -I./include/uapi -I./include/generated/uapi -include ./include/linux/kconfig.h -Iubuntu/include  -D__KERNEL__ -D__ASSEMBLY__ -fno-PIE -m64 -DCONFIG_X86_X32_ABI -DCONFIG_AS_CFI=1 -DCONFIG_AS_CFI_SIGNAL_FRAME=1 -DCONFIG_AS_CFI_SECTIONS=1 -DCONFIG_AS_SSSE3=1 -DCONFIG_AS_AVX=1 -DCONFIG_AS_AVX2=1 -DCONFIG_AS_AVX512=1 -DCONFIG_AS_SHA1_NI=1 -DCONFIG_AS_SHA256_NI=1 -DCC_USING_FENTRY -I'/home/user/working/build'/include  -DMODULE  -c -o /home/user/working/microv/shim/linux/../../hypercall/src/linux/x64/amd/mv_pp_op_clr_shared_page_gpa_impl.o /home/user/working/microv/shim/linux/../../hypercall/src/linux/x64/amd/mv_pp_op_clr_shared_page_gpa_impl.S

source_/home/user/working/microv/shim/linux/../../hypercall/src/linux/x64/amd/mv_pp_op_clr_shared_page_gpa_impl.o := /home/user/working/microv/shim/linux/../../hypercall/src/linux/x64/amd/mv_pp_op_clr_shared_page_gpa_impl.S

deps_/home/user/working/microv/shim/linux/../../hypercall/src/linux/x64/amd/mv_pp_op_clr_shared_page_gpa_impl.o := \
  include/linux/kconfig.h \
    $(wildcard include/config/cpu/big/endian.h) \
    $(wildcard include/config/booger.h) \
    $(wildcard include/config/foo.h) \

/home/user/working/microv/shim/linux/../../hypercall/src/linux/x64/amd/mv_pp_op_clr_shared_page_gpa_impl.o: $(deps_/home/user/working/microv/shim/linux/../../hypercall/src/linux/x64/amd/mv_pp_op_clr_shared_page_gpa_impl.o)

$(deps_/home/user/working/microv/shim/linux/../../hypercall/src/linux/x64/amd/mv_pp_op_clr_shared_page_gpa_impl.o):
