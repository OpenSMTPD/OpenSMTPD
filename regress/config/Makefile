FILES = test0.conf
FILES+= test1.conf
FILES+= test2.conf
FILES+= test3.conf
FILES+= test4.conf
FILES+= test5.conf
FILES+= test6.conf
FILES+= test7.conf
FILES+= test8.conf
FILES+= test9.conf
FILES+= test10.conf
FILES+= test11.conf

test:
.for FILE in $(FILES)
	smtpd -n -f $(FILE)
.endfor
