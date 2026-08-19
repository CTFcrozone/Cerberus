KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)

.PHONY: all clean

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules LLVM=1
	@mkdir -p build
	@mv orthrus.ko build/ 2>/dev/null || true

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean LLVM=1
	@rm -f build/orthrus.ko