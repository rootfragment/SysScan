obj-m += kaslr_offset.o
obj-m += syscall_reporter.o
obj-m += hashed_syscall_reporter.o

#Low yield syscalls
#ToDo- increase syscalls numbers and make it customizable
SYSCALL1 := __x64_sys_getpid
SYSCALL2 := __x64_sys_getuid
SYSCALL3 := __x64_sys_getgid

#parse for calls
_ADDR1 := $(shell sudo grep -E " [tT] $(SYSCALL1)$$" /boot/System.map-$(shell uname -r) | awk '{print $$1}')
_ADDR2 := $(shell sudo grep -E " [tT] $(SYSCALL2)$$" /boot/System.map-$(shell uname -r) | awk '{print $$1}')
_ADDR3 := $(shell sudo grep -E " [tT] $(SYSCALL3)$$" /boot/System.map-$(shell uname -r) | awk '{print $$1}')

#error catch 
$(if $(_ADDR1),,$(error [Makefile] $(SYSCALL1) not found in System.map))
$(if $(_ADDR2),,$(error [Makefile] $(SYSCALL2) not found in System.map))
$(if $(_ADDR3),,$(error [Makefile] $(SYSCALL3) not found in System.map))

STATIC_ADDR1 := 0x$(_ADDR1)
STATIC_ADDR2 := 0x$(_ADDR2)
STATIC_ADDR3 := 0x$(_ADDR3)

ccflags-y := -DSTATIC_ADDR1=$(STATIC_ADDR1) -DSYSCALL1_NAME='"$(SYSCALL1)"' \
             -DSTATIC_ADDR2=$(STATIC_ADDR2) -DSYSCALL2_NAME='"$(SYSCALL2)"' \
             -DSTATIC_ADDR3=$(STATIC_ADDR3) -DSYSCALL3_NAME='"$(SYSCALL3)"'

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
