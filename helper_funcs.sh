#!/bin/bash

NO_COLOR="\e[0m"
WHITE="\e[0;17m"
BOLD_WHITE="\e[1;37m"
BLACK="\e[0;30m"
BOLD_BLACK="\e[1;30m"
BLUE="\e[0;34m"
BOLD_BLUE="\e[1;34m"
GREEN="\e[0;32m"
BOLD_GREEN="\e[1;32m"
CYAN="\e[0;36m"
BOLD_CYAN="\e[1;36m"
RED="\e[0;31m"
BOLD_RED="\e[1;31m"
PURPLE="\e[0;35m"
BOLD_PURPLE="\e[1;35m"
BROWN="\e[0;33m"
BOLD_YELLOW="\e[1;33m"
GRAY="\e[0;37m"
BOLD_GRAY="\e[1;30m"
LIGHTBLUE='\e[2;46m'
LIGHTRED='\e[4;31m'
LIGHTYELLOW='\e[2;33m'

BACKGROUND_WHITE='\e[47m'
BACKGROUND_BLACK='\e[100m'
BACKGROUND_GREEN='\e[102m'

NC='\e[0m'

function print_good () {
    echo -e "${BACKGROUND_BLACK}${BOLD_GREEN}[${1} : $(date +%F)]\t${BOLD_GREEN}[+]${NC} # ${BOLD_BLACK}${BACKGROUND_WHITE} $2 ${NC} #"
}

function print_error () {
    echo -e "${BACKGROUND_BLACK}${BOLD_RED}[${1} : $(date +%F)]\t${BOLD_RED}[!!]${NC} # ${BOLD_BLACK}${BACKGROUND_WHITE} $2 ${NC} #"
}

function print_info () {
    echo -e "${BACKGROUND_BLACK}${BOLD_WHITE}[${1} : $(date +%F)]\t[?]${NC} # ${BOLD_BLACK}${BACKGROUND_WHITE} $2 ${NC} #"
}

function print_warning () {
    echo -e "${BACKGROUND_BLACK}${BOLD_YELLOW}[${1} : $(date +%F)]\t${BOLD_YELLOW}[!]${NC} # ${BOLD_BLACK}${BACKGROUND_WHITE} $2 ${NC} #"
}

function print_menu () {
    echo -e "${BOLD_BLUE}${1}${BOLD_WHITE} ${2}${NC}"
}
