# this path may be different on your system. adjust it accordingly.
CAPSTONE_PATH=/usr/local/Cellar/capstone/3.0.4/include

all:
	clang -m32 -Wl,-pagezero_size,0 main.m ropnroll/ropnroll.c ropnroll/macho/rnr_macho.c ropnroll/gadgets/rnr_gadgets.c ropnroll/glue.m -framework Foundation -framework IOKit -I$(CAPSTONE_PATH) -Llib/ -lcapstone.3 -o stfusip

clean:
	rm -rf stfusip
