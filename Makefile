main: main.c
	clang -fshow-column -fshow-source-location -fcaret-diagnostics -fdiagnostics-format=clang -fdiagnostics-show-option -fdiagnostics-show-category=name -fdiagnostics-fixit-info -std=c89 -fcolor-diagnostics -pedantic -pedantic-errors -Werror -Weverything -Wno-format-nonliteral -lcrypto -o main main.c

.PHONY:
test: test-password test-dh-key test-rsa-key

.PHONY:
test-bigfile: main
	echo "----- Testing encryption of a big file -----"
	dd if=/dev/urandom of=temporarytestingfile bs=1k count=101
	echo -e 'password\nraktas\nne' | (echo && ./main uzsifruoti temporarytestingfile main.c.encrypted) && echo -e 'password\nraktas' | (echo && ./main issifruoti main.c.encrypted temporarytestingfile.decrypted) && diff -ru temporarytestingfile temporarytestingfile.decrypted
	rm temporarytestingfile temporarytestingfile.decrypted

.PHONY:
test-password: main
	echo "----- Testing encryption with password -----"
	echo -e 'password\nraktas\nne' | (echo && ./main uzsifruoti main.c main.c.encrypted) && echo -e 'password\nraktas' | (echo && ./main issifruoti main.c.encrypted main.c.decrypted) && diff -ru main.c main.c.decrypted

.PHONY:
test-dh-key: main
	echo "----- Testing encryption with dh key exchange -----"
	echo -e 'dh\na_private.pem\na_public.pem' | ./main sukurtiraktus
	echo -e 'dh\nb_private.pem\nb_public.pem' | ./main sukurtiraktus
	echo -e 'dh\na_private.pem\nb_public.pem\nne' | (echo && ./main uzsifruoti main.c main.c.encrypted) && echo -e 'dh\nb_private.pem\na_public.pem' | (echo && ./main issifruoti main.c.encrypted main.c.decrypted) && diff -ru main.c main.c.decrypted

.PHONY:
test-rsa-key: main
	echo "----- Testing encryption with rsa key exchange -----"
	echo -e 'rsa\nb_private.pem\nb_public.pem' | ./main sukurtiraktus
	echo -e 'rsa\nb_public.pem\nne' | (echo && ./main uzsifruoti main.c main.c.encrypted) && echo -e 'rsa\nb_private.pem' | (echo && ./main issifruoti main.c.encrypted main.c.decrypted) && diff -ru main.c main.c.decrypted

.PHONY:
clean:
	rm -f main
