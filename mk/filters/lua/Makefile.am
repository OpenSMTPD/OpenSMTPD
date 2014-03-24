include $(top_srcdir)/mk/pathnames
include $(top_srcdir)/mk/filter.mk

pkglibexec_PROGRAMS	 = filter-lua

filter_lua_SOURCES	 = $(SRCS)
filter_lua_SOURCES	 += $(filters_srcdir)/filter_lua.c
filter_lua_CFLAGS	 = `pkg-config --cflags lua-5.2`
filter_lua_LDFLAGS	 = `pkg-config --libs lua-5.2`
