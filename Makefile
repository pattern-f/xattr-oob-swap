all:
	cc exploit-1/*.c mylib/*.c -I./mylib -framework IOKit -o exploit
	sync
