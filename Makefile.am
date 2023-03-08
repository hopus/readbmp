

ACLOCAL_AMFLAGS = -I m4

vimtest: all
	## ddd -args ./bulkrays --bind=127.0.0.1:10080 --user=$$USER --access_log=access_log --earlylog --console --p tagazou zonzon=2 p=3 BulkRays::ownsetoftests &
	## exit 0
	## ./hcpp2cpp testbb.hcpp -o testbb.cpp
	##
	## ./readbmp --maxmessage=1000
	##
	./readbmp --bind=0.0.0.0:10000 --connect=127.0.0.1:5028 --maxmessage=40

###    2>&1 | unbuffer -p tr ':' '='

bin_PROGRAMS = readbmp

#### hcpp2cpp_SOURCES = hcpp2cpp.cpp

readbmp_SOURCES = readbmp.cpp
readbmp_LDADD = @QICONNSOURCE@/libqiconn.a

		   
%.cc: %.hcpp hcpp2cpp
	./hcpp2cpp $< -o $@

doc: include/readbmp/*.h *.cpp readbmp.dox
	doxygen readbmp.dox

#### CLEANFILES = readbmp.cc simplefmap.cc access_log

clean-local:
	cd @QICONNSOURCE@ && make clean
	rm -rf readme-doc

distclean-local:
	cd @QICONNSOURCE@ && make distclean
	rm m4/*.m4
	rm -rf refdocs

.PHONY: refdocs

refdocs: ref_list.txt
	[ -d refdocs ] && : || mkdir refdocs
	## cd refdocs && cat ../ref_list.txt | sed -E 's/^[[:space:]]+//' | cut -f1 | grep -v '^$$' | while read NOM ; do if [ $$( echo "$$NOM" | cut -b1-3) = "rfc" ] ; then wget "https://www.rfc-editor.org/rfc/$${NOM}.txt" -O "$${NOM}".txt ; else wget "$${NOM}" ; fi ; done
	cd refdocs && cat ../ref_list.txt | sed -E 's/^[[:space:]]+//' | sed -E 's/[[:space:]]+/ /g' | grep -v '^$$' | while read NOM TITLE ; do TITLE=$$( echo "$$TITLE" | cut -d '[' -f1 | sed 's/[[:space:]]*$$//' | tr '/' '-') ; if [ $$( echo "$$NOM" | cut -b1-3) = "rfc" ] ; then wget --no-verbose "https://www.rfc-editor.org/rfc/$${NOM}.txt" -O "$${NOM} - $${TITLE}".txt ; else wget --no-verbose "$${NOM}" -O "$${TITLE}".txt ; fi ; done

@QICONNSOURCE@/configure:
	cd @QICONNSOURCE@ && autoall

@QICONNSOURCE@/Makefile: @QICONNSOURCE@/configure
	cd @QICONNSOURCE@ && ./configure -prefix=$(prefix)

@QICONNSOURCE@/libqiconn.a: @QICONNSOURCE@/qiconn.cpp @QICONNSOURCE@/qiconn/qiconn.h @QICONNSOURCE@/Makefile
	cd @QICONNSOURCE@ && make libqiconn.a

