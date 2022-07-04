search-symtab-rel-helper.so: search-symtab-rel-helper.c
	gcc -O1 -shared -o search-symtab-rel-helper.so search-symtab-rel-helper.c
