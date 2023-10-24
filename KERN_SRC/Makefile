
mao-module-name	:= MaoLinuxModuleTemplate
mao-obj-ko	:= $(mao-module-name).ko
obj-m		:= $(mao-module-name).o
ccflags-m	:= -O2

PWD			:= $(shell pwd)
KERN_SRC	:= /lib/modules/$(shell uname -r)/build/
Mao_MODULE_INSTALL_DIR	:= /lib/modules/$(shell uname -r)/

modules:
	#
	#   ==================== Mao Building ====================
	#
	make -C $(KERN_SRC) M=$(PWD) modules
	#
	#   ==================== Mao Signing ====================
	#
	# $(KERN_SRC)/scripts/sign-file sha512 $(KERN_SRC)/certs/signing_key.pem $(KERN_SRC)/certs/signing_key.x509 $(mao-obj-ko)
	#
	#   ==================== Mao Installing ====================
	#
	cp $(mao-obj-ko) $(Mao_MODULE_INSTALL_DIR)
	#
	#   ==================== Mao Indexing ====================
	#
	depmod -a

info:
	modinfo $(mao-module-name)

#install:
#	make -C $(KERN_SRC) M=$(PWD) modules_install
#	depmod -a

clean:
	make -C $(KERN_SRC) M=$(PWD) clean
