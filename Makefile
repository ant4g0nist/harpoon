harpoon64: test.c harpoon64.c
	gcc -g test.c -framework CoreServices -Wno-implicit libudis86/*.c harpoon64.c -o test
	#gcc testlib.c harpoon64.c libudis86/*.c -dynamiclib -o libTest.dylib -Wno-deprecated-declarations -DDEBUG
