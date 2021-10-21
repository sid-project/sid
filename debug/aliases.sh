alias autogen-sid='echo -e "\n ========== AUTOGENERATING =====\n ..."; ./autogen.sh'
alias configure-sid='echo -e "\n ========== CONFIGURING ========\n ..."; ./configure --disable-static --with-systemdsystemunitdir=/etc/systemd/system --with-udevrulesdir=/etc/udev/rules.d CC=clang'
alias configure-sid-gcc='echo -e "\n ========== CONFIGURING ========\n ..."; ./configure --disable-static --with-systemdsystemunitdir=/etc/systemd/system --with-udevrulesdir=/etc/udev/rules.d CC=gcc'
alias configure-sid-g++='echo -e "\n ========== CONFIGURING ========\n ..."; ./configure --disable-static --with-systemdsystemunitdir=/etc/systemd/system --with-udevrulesdir=/etc/udev/rules.d CC=g++'
alias build-sid='echo -e "\n ========== BUILDING ===========\n ..."; make V=1 2>&1 | tee .mk.log; \
                 echo -e "\n ========== ERROR LOG ==========\n ..."; grep -E "Error [0-9]*|.*:[0-9]*:[0-9]*: error:" < .mk.log; \
		 echo -e "\n ========== WARNING LOG ========\n ..."; grep -E ".*:[0-9]*:[0-9]*: warning:" < .mk.log; \
                 echo -e "\n ========== UNDEFINED REFS =====\n"; grep -E "undefined reference to " < .mk.log; \
		 echo -e "\n"'
alias install-sid='echo -e "\n ========== INSTALLING =========\n ..."; make install'
alias reload-sid='echo -e "\n ========== RELOADING =========\n ..." \ 
	          echo -e "reloading udev rules...\n"; udevadm control -R; \
		  echo -e "reloading systemd daemon...\n"; systemctl daemon-reload'
alias setup-sid='echo -e "\n ========== SETTING UP =========\n ..."; \
		 echo -e "stopping possibly running sid.service unit...\n"; systemctl stop sid sid.socket; \
		 echo -e "restarting sid.socket unit...\n"; systemctl restart sid.socket'
alias libs-sid='echo -en "Adding /usr/local/lib/sid to LD_LIBRARY_PATH... "; if [[ $LD_LIBRARY_PATH =~ :/usr/local/lib/sid($|:) ]]; then echo "already there"; else export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/usr/local/lib/sid; echo "added"; fi'
alias all-sid='autogen-sid; configure-sid; build-sid; install-sid; reload-sid; setup-sid; libs-sid'
alias all-sid-nosetup='autogen-sid; configure-sid; build-sid; install-sid; reload-sid; libs-sid'

alias sid-dbdump-jq='sidctl dbdump -f json | jq -C --tab | less -r'
