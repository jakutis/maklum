.PHONY:
default:
	make clean
	make main
	echo -e 'bronius\n1\nraktas\ntaip' | (echo && ./main uzsifruoti main.c encrypted)

main: main.c
	clang -fshow-column -fshow-source-location -fcaret-diagnostics -fdiagnostics-format=clang -fdiagnostics-show-option -fdiagnostics-show-category=name -fdiagnostics-fixit-info -std=c89 -fcolor-diagnostics -pedantic -pedantic-errors -Werror -Weverything -lcrypto -o main main.c

.PHONY:
clean:
	rm -f main
