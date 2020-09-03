alias autogen-sid='echo -e "\n ========== AUTOGENERATING =====\n ..."; ./autogen.sh'
alias configure-sid='echo -e "\n ========== CONFIGURING ========\n ..."; ./configure --with-systemdsystemunitdir=/etc/systemd/system --with-udevrulesdir=/etc/udev/rules.d CC=clang'
alias build-sid='echo -e "\n ========== BUILDING ===========\n ..."; make V=1 2>&1 | tee .mk.log; \
                 echo -e "\n ========== ERROR LOG ==========\n ..."; grep -E "Error [0-9]*|.*:[0-9]*:[0-9]*: error:" < .mk.log; \
		 echo -e "\n ========== WARNING LOG ========\n ..."; grep -E ".*:[0-9]*:[0-9]*: warning:" < .mk.log; \
                 echo -e "\n ========== UNDEFINED REFS =====\n"; grep -E "undefined reference to " < .mk.log; \
		 echo -e "\n"'
alias install-sid='echo -e "\n ========== INSTALLING =========\n ..."; make install'
alias setup-sid='echo -e "\n ========== SETTING UP =========\n ..."; systemctl daemon-reload; systemctl stop sid; systemctl restart sid.socket'
alias all-sid='autogen-sid; configure-sid; build-sid; install-sid; setup-sid'
