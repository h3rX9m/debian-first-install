# ~/.bashrc: executed by bash(1) for non-login shells.
# see /usr/share/doc/bash/examples/startup-files (in the package bash-doc)
# for examples

# If not running interactively, don't do anything
[ -z "$PS1" ] && return

# don't put duplicate lines or lines starting with space in the history.
# See bash(1) for more options
HISTCONTROL=ignoreboth

# append to the history file, don't overwrite it
shopt -s histappend

# for setting history length see HISTSIZE and HISTFILESIZE in bash(1)
HISTSIZE=1000
HISTFILESIZE=2000
export HISTTIMEFORMAT="%d/%m/%y %T "

# check the window size after each command and, if necessary,
# update the values of LINES and COLUMNS.
shopt -s checkwinsize

# If set, the pattern "**" used in a pathname expansion context will
# match all files and zero or more directories and subdirectories.
shopt -s globstar

# make less more friendly for non-text input files, see lesspipe(1)
[ -x /usr/bin/lesspipe ] && eval "$(SHELL=/bin/sh lesspipe)"

# set variable identifying the chroot you work in (used in the prompt below)
if [ -z "$debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# set a fancy prompt (non-color, unless we know we "want" color)
case "$TERM" in
    xterm-color) color_prompt=yes;;
esac

# uncomment for a colored prompt, if the terminal has the capability; turned
# off by default to not distract the user: the focus in a terminal window
# should be on the output of commands, not on the prompt
force_color_prompt=yes

if [ -n "$force_color_prompt" ]; then
    if [ -x /usr/bin/tput ] && tput setaf 1 >&/dev/null; then
  # We have color support; assume it's compliant with Ecma-48
  # (ISO/IEC-6429). (Lack of such support is extremely rare, and such
  # a case would tend to support setf rather than setaf.)
  color_prompt=yes
    else
  color_prompt=
    fi
fi
if [ $UID -ne 0 ]; then
  if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;32m\]\u\[\033[01;34m\]@\H:\[\033[01;36m\]\w\[\033[01;32m\] \$\[\033[00m\] '
  else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
  fi
else
  if [ "$color_prompt" = yes ]; then
    PS1='${debian_chroot:+($debian_chroot)}\[\033[01;31m\]\u\[\033[01;34m\]@\h:\[\033[01;31m\]\w\[\033[01;31m\] \$\[\033[00m\] '
  else
    PS1='${debian_chroot:+($debian_chroot)}\u@\h:\w\$ '
  fi
fi

unset color_prompt force_color_prompt

# If this is an xterm set the title to user@host:dir
case "$TERM" in
xterm*|rxvt*)
    PS1="\[\e]0;${debian_chroot:+($debian_chroot)}\u@\h: \w\a\]$PS1"
    ;;
*)
    ;;
esac

# enable color support of ls and also add handy aliases
if [ -x /usr/bin/dircolors ]; then
    test -r ~/.dircolors && eval "$(dircolors -b ~/.dircolors)" || eval "$(dircolors -b)"
    alias ls='ls --color=auto'
    alias dir='dir --color=auto'
    alias vdir='vdir --color=auto'

    alias grep='grep --color=auto'
    alias fgrep='fgrep --color=auto'
    alias egrep='egrep --color=auto'
fi

#######################
## SOME MORE ALIASES ##
#######################
alias halt="echo DON\'T STOP ME NOOOWWWW - Queen"
alias shutdown="echo DON\'T STOP ME NOOOWWWW - Queen"
alias poweroff="echo DON\'T STOP ME NOOOWWWW - Queen"
alias ll='ls -lhA'
alias la='ls -A'
alias l='ls -CF'
alias wanip='dig +short myip.opendns.com @resolver1.opendns.com'
alias su='su -'
alias ..='cd ..'
alias ...='cd ../../'
alias mkdir='mkdir -pv'
alias diff='colordiff'
alias path='echo -e ${PATH//:/\\n}'
alias now='date +"%D %T"'
alias nowtime='date +"%T"'
alias nowdate='date +"%d-%m-%Y"'
alias ping='ping -c 5'
alias fastping='ping -c 50 -s.2'
alias ports='netstat -tulanp'
alias meminfo='free -m -l -t'
alias psmem='ps auxf | sort -nr -k 4 | head -10'
alias pscpu='ps auxf | sort -nr -k 3 | head -10'
alias cpuinfo='lscpu'
alias wget='wget -c'
function ipshow() { [ -z "$*" ] && { ip a | awk '/inet / { print $(NF),$2 }'; } || { for if in $*; do ip a | awk '/inet / { print $(NF),$2 }' | grep $if ;done; }; }
if [ $UID -ne 0 ]; then
  alias reboot='sudo reboot; exit'
  alias upgrade='sudo apt-get -qq update; sudo apt-get -qqy upgrade; sudo apt-get -qqy autoclean'
  alias build='./configure && make && sudo make install'
  alias localip="sudo ifconfig | grep cast | cut -d':' -f2 | cut -d' ' -f1"
  alias ipt='sudo /sbin/iptables'
  alias iptlist='sudo /sbin/iptables -L -n -v --line-numbers'
  alias iptnat='sudo /sbin/iptables -t nat -L -n -v --line-numbers; sudo /sbin/iptables -L FORWARD -n -v --line-numbers'
  alias iptlistin='sudo /sbin/iptables -L INPUT -n -v --line-numbers'
  alias iptlistout='sudo /sbin/iptables -L OUTPUT -n -v --line-numbers'
  alias iptlistfw='sudo /sbin/iptables -L FORWARD -n -v --line-numbers'
  function iptaddpack() { [ -z "$*" ] && { echo "$(tput setaf 2)Usage: iptaddpack package_server_name_1 package_server_name_2...$(tput sgr 0)"; } || { for name in $*; do sudo sed -i "s@$(cat /etc/bash_completion.d/iptdelpack | grep list= | sed 's/.$//g')@$(cat /etc/bash_completion.d/iptdelpack | grep list= | sed "s/.$/$name/g") @" /etc/bash_completion.d/iptdelpack; sudo iptables -t filter -A PACKAGE_SERVER -o PUB_IF -p tcp -s SERVER_IP -d $name -m multiport --dports 21,80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT; sudo iptables -t filter -A PACKAGE_SERVER -i PUB_IF -p tcp -s $name -d SERVER_IP -m multiport --sports 21,80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT; done; source /etc/bash_completion.d/iptdelpack; }; }
  function iptdelpack() { [ -z "$*" ] && { echo "$(tput setaf 2)Usage: iptdelpack package_servers_name_1 package_servers_name_2...$(tput sgr 0)"; } || { for name in $*; do sudo sed -i "s/$name //" /etc/bash_completion.d/iptdelpack; sudo iptables -t filter -D PACKAGE_SERVER -o PUB_IF -p tcp -s SERVER_IP -d $name -m multiport --dports 21,80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT; sudo iptables -t filter -D PACKAGE_SERVER -i PUB_IF -p tcp -s $name -d SERVER_IP -m multiport --sports 21,80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT; done; source /etc/bash_completion.d/iptdelpack; }; }
  function iptaddhttp() { [ -z "$*" ] && { echo "$(tput setaf 2)Usage: iptaddhttp server_1 server_2...$(tput sgr 0)"; } || { for name in $*; do sudo sed -i "s@$(cat /etc/bash_completion.d/iptdelhttp | grep list= | sed 's/.$//g')@$(cat /etc/bash_completion.d/iptdelhttp | grep list= | sed "s/.$/$name/g") @" /etc/bash_completion.d/iptdelhttp; sudo iptables -t filter -A SPECIFIC_WEBSITE -o PUB_IF -p tcp -s SERVER_IP -d $name -m multiport --dports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT; sudo iptables -t filter -A SPECIFIC_WEBSITE -i PUB_IF -p tcp -s $name -d SERVER_IP -m multiport --sports 80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT; done; source /etc/bash_completion.d/iptdelhttp; }; }
  function iptdelhttp() { [ -z "$*" ] && { echo "$(tput setaf 2)Usage: iptdelhttp server_1 server_2...$(tput sgr 0)"; } || { for name in $*; do sudo sed -i "s/$name //" /etc/bash_completion.d/iptdelhttp; sudo iptables -t filter -D SPECIFIC_WEBSITE -o PUB_IF -p tcp -s SERVER_IP -d $name -m multiport --dports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT; sudo iptables -t filter -D SPECIFIC_WEBSITE -i PUB_IF -p tcp -s $name -d SERVER_IP -m multiport --sports 80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT; done; source /etc/bash_completion.d/iptdelhttp; }; }
else
  alias rm='rm -i'
  alias mv='mv -i'
  alias reboot='reboot; exit'
  alias upgrade='apt-get -qq update; apt-get -qqy upgrade; apt-get -qqy autoclean'
  alias build='./configure && make && make install'
  alias localip="ifconfig | grep cast | cut -d':' -f2 | cut -d' ' -f1"
  alias ipt='/sbin/iptables'
  alias iptlist='/sbin/iptables -L -n -v --line-numbers'
  alias iptnat='/sbin/iptables -t nat -L -n -v --line-numbers; /sbin/iptables -L FORWARD -n -v --line-numbers'
  alias iptlistin='/sbin/iptables -L INPUT -n -v --line-numbers'
  alias iptlistout='/sbin/iptables -L OUTPUT -n -v --line-numbers'
  alias iptlistfw='/sbin/iptables -L FORWARD -n -v --line-numbers'
  function init() { if [[ $@ == "0" ]]; then command echo "DON'T STOP ME NOWWWW - Queen"; fi; }
  function iptaddpack() { [ -z "$*" ] && { echo "$(tput setaf 2)Usage: iptaddpack package_server_name_1 package_server_name_2...$(tput sgr 0)"; } || { for name in $*; do sed -i "s@$(cat /etc/bash_completion.d/iptdelpack | grep list= | sed 's/.$//g')@$(cat /etc/bash_completion.d/iptdelpack | grep list= | sed "s/.$/$name/g") @" /etc/bash_completion.d/iptdelpack; iptables -t filter -A PACKAGE_SERVER -o PUB_IF -p tcp -s SERVER_IP -d $name -m multiport --dports 21,80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT; iptables -t filter -A PACKAGE_SERVER -i PUB_IF -p tcp -s $name -d SERVER_IP -m multiport --sports 21,80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT; done; source /etc/bash_completion.d/iptdelpack; }; }
  function iptdelpack() { [ -z "$*" ] && { echo "$(tput setaf 2)Usage: iptdelpack package_servers_name_1 package_servers_name_2...$(tput sgr 0)"; } || { for name in $*; do sed -i "s/$name //" /etc/bash_completion.d/iptdelpack; iptables -t filter -D PACKAGE_SERVER -o PUB_IF -p tcp -s SERVER_IP -d $name -m multiport --dports 21,80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT; iptables -t filter -D PACKAGE_SERVER -i PUB_IF -p tcp -s $name -d SERVER_IP -m multiport --sports 21,80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT; done; source /etc/bash_completion.d/iptdelpack; }; }
  function iptaddhttp() { [ -z "$*" ] && { echo "$(tput setaf 2)Usage: iptaddhttp server_1 server_2...$(tput sgr 0)"; } || { for name in $*; do sed -i "s@$(cat /etc/bash_completion.d/iptdelhttp | grep list= | sed 's/.$//g')@$(cat /etc/bash_completion.d/iptdelhttp | grep list= | sed "s/.$/$name/g") @" /etc/bash_completion.d/iptdelhttp; iptables -t filter -A SPECIFIC_WEBSITE -o PUB_IF -p tcp -s SERVER_IP -d $name -m multiport --dports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT; iptables -t filter -A SPECIFIC_WEBSITE -i PUB_IF -p tcp -s $name -d SERVER_IP -m multiport --sports 80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT; done; source /etc/bash_completion.d/iptdelhttp; }; }
  function iptdelhttp() { [ -z "$*" ] && { echo "$(tput setaf 2)Usage: iptdelhttp server_1 server_2...$(tput sgr 0)"; } || { for name in $*; do sed -i "s/$name //" /etc/bash_completion.d/iptdelhttp; iptables -t filter -D SPECIFIC_WEBSITE -o PUB_IF -p tcp -s SERVER_IP -d $name -m multiport --dports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT; iptables -t filter -D SPECIFIC_WEBSITE -i PUB_IF -p tcp -s $name -d SERVER_IP -m multiport --sports 80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT; done; source /etc/bash_completion.d/iptdelhttp; }; }
fi
git () { iptaddhttp github.com; /usr/bin/git $1 $2; iptdelhttp github.com; }

# Alias definitions.
# You may want to put all your additions into a separate file like
# ~/.bash_aliases, instead of adding them here directly.
# See /usr/share/doc/bash-doc/examples in the bash-doc package.

if [ -f ~/.bash_aliases ]; then
    . ~/.bash_aliases
fi

# enable programmable completion features (you don't need to enable
# this, if it's already enabled in /etc/bash.bashrc and /etc/profile
# sources /etc/bash.bashrc).
if ! shopt -oq posix; then
  if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion
  elif [ -f /etc/bash_completion ]; then
    . /etc/bash_completion
  fi
fi

function extract {
 if [ -z "$1" ]; then
    # display usage if no parameters given
    echo "Usage: extract <path/file_name>.<zip|rar|bz2|gz|tar|tbz2|tgz|Z|7z|xz|ex|tar.bz2|tar.gz|tar.xz>"
 else
    if [ -f $1 ] ; then
        # NAME=${1%.*}
        # mkdir $NAME && cd $NAME
        case $1 in
          *.tar.bz2)   tar xvjf ../$1    ;;
          *.tar.gz)    tar xvzf ../$1    ;;
          *.tar.xz)    tar xvJf ../$1    ;;
          *.lzma)      unlzma ../$1      ;;
          *.bz2)       bunzip2 ../$1     ;;
          *.rar)       unrar x -ad ../$1 ;;
          *.gz)        gunzip ../$1      ;;
          *.tar)       tar xvf ../$1     ;;
          *.tbz2)      tar xvjf ../$1    ;;
          *.tgz)       tar xvzf ../$1    ;;
          *.zip)       unzip ../$1       ;;
          *.Z)         uncompress ../$1  ;;
          *.7z)        7z x ../$1        ;;
          *.xz)        unxz ../$1        ;;
          *.exe)       cabextract ../$1  ;;
          *)           echo "extract: '$1' - unknown archive method" ;;
        esac
    else
        echo "$1 - file does not exist"
    fi
fi
}

