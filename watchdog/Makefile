KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

.PHONY: all clean

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules LLVM=1
	@mkdir -p build
	@find . -path ./build -prune -o -name '*.ko' -exec mv {} build/ \;
	@find . -path ./build -prune -o \( \
		-name '*.o' -o -name '*.mod' -o -name '*.mod.c' \
		-o -name '.*.cmd' -o -name 'modules.order' \
		-o -name 'Module.symvers' -o -name '*.symvers' \
	\) -exec rm -f {} +
	@rm -rf .tmp_versions

listener: tools/test_listener.c
	cc -Wall -Iinclude -o build/test_listener tools/test_listener.c

clean:
	@rm -rf build