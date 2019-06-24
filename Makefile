ifeq ($(ANOPE),)
  $(error Usage: make ANOPE=/path/to/anope/tree)
endif

import:

$(ANOPE)/modules/os_trace.cpp:
	ln -s $(abspath os_trace.cpp) $@

$(ANOPE)/modules/os_trace:
	ln -s $(abspath os_trace) $@
