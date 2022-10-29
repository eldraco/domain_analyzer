#! /usr/bin/env python
#  Copyright (C) 2009  Sebastian Garcia, Veronica Valeros
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# MatesLab www.mateslab.com.ar
#
#
# Authors:
# Sebastian Garcia eldraco@gmail.com
# Veronica Valeros vero.valeros@gmail.com
#
# Thanks to Gustavo Sorondo iampuky@gmail.com for contributing the common hosts list code.
#
# Changelog
# 0.8.1
#       - Small delete of few debug options
# 0.8
#       - Added "-L --common-hosts-list" option to read the common hosts list from a text file.
# 0.7
#       - Changed robtex web url.
# 0.6
#    - Some minor bug fixes when dealing with host that do not have a host name or a PTR record.
# 0.5   
#       - Added an option to download files from the crawler to the output directory
#       - Now crawler results are obtained ok
#       - Old udp option was deleted
#     - Adds http://www.robtex.com information for every domain and the domain searched!. In http://www.robtex.com/dns/<domain>.html we can find other domains that use THIS dns server. Useful if the NS has zone transfer!!!
#     - Check first if what was given was a domain
#    - More gtld subdomains added, like 'co', 'go' and 'ag'.
#    - Some minor options name fix
#     - If host has some pattern given by the user (like google) do not check it with nmap
#     - Some dns are broken and gets into a loop! We do not follow them!
#     - Now we randomly find X domain in internet and analyze them
#     - Store every line in the output file, not just the summary
#    - We avoid adding subdomains if we found a broken DNS server with recursive subdomains
#    - Now we also print out in the output file what is going on during the analysis and we don't wait until we finish to print everything out.
#     - Check SPF record, looking for ip addresses and hostnames
#     - We store in the output file the new subdomains found and in the printout
#    - Now xml stylesheet is used.
#    - Nmap scripts results are parsed and used.
#    - A LOT of aesthetical fixes!
#    - We look for PTR records, and alert when hostname and PTR are different
#    - Now every host found in sL is added to the Ip list
#    - Print everything in colors! Including the critical ports as a warning!
#    - Now we print the country of every IP!
#    - Some minor bug fixes
#    - Now netblocks are extracked well, and netblocks are checked only once.
#    - Add printing the hostname when scanning ports
#    - We developed a web crawler serching for web things. It is external.
#    - We create a pdf report from the text file
#    - We added subdomains automatic analysis. It can found recursive subdomains!
#    - We added email searching for that domain in google sets and google
# 0.4   
#    - Fixed a bug that prevented this to work fine under Debian systems. (Something with False!="" exploting)
#    - Now the directory is not created until we know some DNS servers exist
#    - Now if the domain does not exists, we exit
#    - We use zenmap to show the topology of the hosts.
#    - A parameter not to store nmap output files on disk
#    - We create an output directory with everything into it.
#    - A parameter -z to only scan host in the zone transfer. This is now stored correctly.
#    - some minor typo fixes
# 0.3  
#     - A parameter not to scan with nmap
#     - A parameter to do everything only when ZT is successful
# 0.2 New filename without dash
#    Fixed a bug that we try to store in disk without opening the file
# 0.1 feb 2 2011: Creation
#
# TODO
# - We still don't read every nmap results 
# - OBTAIN THE CRAWLER RESULTS CORRECLTY!!!
# - Use threads to improve the performance.
# - Create a tar.gz with everything!
# - Add the last router in the traceroute to the analysis.
# - Compute and print statistics about the problems found sorted by country/domain
# - Be tor-friendly. Detect tor is being used and Use tor-resolve or something.
# - Detect and count DNS missconfigurations
# - Zenmap does not work fine with multiple subdomains, it keeps opening the main domain only
# - From inside a network with a web proxy, sometimes zone transfer does not work and every domain seems to have wilcards!. To identify this
#    perhaps is useful to try to make a ZT froma known public domain. If it does not occur, then the internal network is filtering!
# - Have a --robin-hood option, which sends the pdf report to every email found in the domain, using domain MX host.
# - Check domains like with strange characters, like chineese
# - For every version, try to find vulnerabilities!!!!!
# - For every email, search owner information on every social site
# - Make nmap error do not appear in the output
# - Use xsltproc nmap.xml > nmap.html to create web pages with the information
# - Play an audio sound when we found errors!!
# -- Web --
# - Recognize login web pages
# - Run a very light nikto?
# - Make zenmap work in macos
#
# BUGS
# - Nmap ports are printed twice in the printout, and ports are not printed at all during the scan. BOTH IN THE OUTPUT FILE.
#


# standard imports
from subprocess import Popen
from subprocess import PIPE
from subprocess import call
from ansistrm import *
import socket
import os, sys
import getopt
try:
    import dns.resolver
except:
    print 'You need to install python-dnspython. apt-get install python-dnspython'
    sys.exit(-1)
import dns.query
import dns.zone
import copy
import shlex
import time

####################
# Global Variables

# Debug
debug = 0
vernum = "0.8.2"

# domain_data{'IpsInfo'}
#    {
#    '1.1.1.1':    [     {'HostName':'test.com'}, 
#                {'Type':'NS'}, 
#                {'IpCountry':'Peru'}, 
#                {'PTR':'rev.name.pe'}, 
#                {'SubDomain':'other.test.com'}, 
#                {'HostUp': True}, 
#                {'PortInfo':'text'}    
#                {'ScriptInfo':'text'}    
#                {'OSInfo':'Linux'}    
#                {'ZT': 23}    
#                {'DirIndex':}    
#            ]
#    '2.2.2.2':    [
#            ]
#    }

# domain_data{'DomainInfo'}
#    {
#        'Email': 'test@test.com'
#        'Email': 'test2@test.com'
#    }


# Main dictionary
domain_data={}
# First component is for Ip information
domain_data['IpsInfo']={}
# Second component is for Domain information
domain_data['DomainInfo']=[]

# By default check common hostnames
check_common_hosts_names=True

# Default is to scan only TCP ports
nmap_scantype="-O --reason --webxml --traceroute -sS -sV -sC -Pn -n -v -F"

# Default is to transfer the zone
zone_transfer=True

# Default is to scan the netblocks
net_block=True

# Output file
output_file=""

# Default is to scan nmap ports
nmap=1

output_directory=False

not_store_nmap=0

# Default is not to use zenmap
zenmap=0

# Default is not to look for emails using goog-mail.py
googmail=0

# Here we store every subdomain found
subdomains_found=[]

not_goog_mail=True

# By default we DO analyze subdomains recursively
not_subdomains=False

create_pdf=False

# by default do NOT go into robin hood mode. Should this be random???
robin_hood=False

webcrawl=True

common_hostnames=[]

# By default only scan 10 web pages
max_amount_to_crawl=50

# By default do not dominate the world
world_domination=False

# By default resolve country names
countrys=True
geoip_cache=""

colors=True

# If ports found are in this list, then we do not print them as critical
normal_port_list=['21/','22/','25/','53/udp','80/','443/','110/','143/','993/','995/','465/']

check_spf=True

output_file_handler=False

amount_of_random_domains=False

ignore_host_pattern=False

robtex_domains=False

# Here we store the next ns servers to check with robetx
ns_servers_to_robtex={}

domains_still_to_analyze=[]

download_files=False

all_robtex=False

# By default we don't use common hostname list
use_common_list = False
common_list_path = ""

# zenmap command
zenmap_command = 'zenmap'

# End of global variables
###########################



# Print version information 
def version():
  print "+----------------------------------------------------------------------+"
  print "| "+ sys.argv[0] + " Version "+ vernum +"                         |"
  print "| This program is free software; you can redistribute it and/or modify |"
  print "| it under the terms of the GNU General Public License as published by |"
  print "| the Free Software Foundation; either version 2 of the License, or    |"
  print "| (at your option) any later version.                                  |"
  print "|                                                                      |"
  print "| Author: Garcia Sebastian, eldraco@gmail.com                          |"
  print "| Author: Veronica Valeros, vero.valeros@gmail.com                     |"
  print "| www.mateslab.com.ar - Argentina                                      |"
  print "+----------------------------------------------------------------------+"
  print

# Print help information and exit:
def usage():
#  print "+----------------------------------------------------------------------+"
#  print "| "+ sys.argv[0] + " Version "+ vernum +"                         |"
#  print "| This program is free software; you can redistribute it and/or modify |"
#  print "| it under the terms of the GNU General Public License as published by |"
#  print "| the Free Software Foundation; either version 2 of the License, or    |"
#  print "| (at your option) any later version.                                  |"
#  print "|                                                                      |"
#  print "| Author: Garcia Sebastian, eldraco@gmail.com                          |"
#  print "| Author: Veronica Valeros, vero.valeros@gmail.com                     |"
#  print "| www.mateslab.com.ar - Argentina                                      |"
#  print "+----------------------------------------------------------------------+"
  print "\nusage: %s -d <domain> <options>" % sys.argv[0]
  print "options:"
  print "  -h, --help                            Show this help message and exit."
  print "  -V, --version                         Output version information and exit."
  print "  -D, --debug                           Debug."
  print "  -d, --domain                          Domain to analyze."
  print "  -L <list>, --common-hosts-list <list> Relative path to txt file containing common hostnames. One name per line."
  print "  -j, --not-common-hosts-names          Do not check common host names. Quicker but you will lose hosts."
  print "  -t, --not-zone-transfer               Do not attempt to transfer the zone."
  print "  -n, --not-net-block                   Do not attempt to -sL each IP netblock."
  print "  -o, --store-output                    Store everything in a directory named as the domain. Nmap output files and the summary are stored inside."
  print "  -a, --not-scan-or-active              Do not use nmap to scan ports nor to search for active hosts."
  print "  -p, --not-store-nmap                  Do not store any nmap output files in the directory <output-directory>/nmap."
  print "  -e, --zenmap                          Move xml nmap files to a directory and open zenmap with the topology of the whole group. Your user should have access to the DISPLAY variable."
  print "  -g, --not-goog-mail                   Do not use goog-mail.py (embebed) to look for emails for each domain"
  print "  -s, --not-subdomains                  Do not analyze sub-domains recursively. You will lose subdomain internal information."
  print "  -f, --create-pdf                      Create a pdf file with all the information."
  print "  -l, --world-domination                Scan every gov,mil,org and net domains of every country on the world. Interesting if you don't use -s"
  print "  -r, --robin-hood                      Send the pdf report to every email found using domains the MX servers found. Good girl."
  print "  -w, --not-webcrawl                    Do not web crawl every web site (in every port) we found looking for public web mis-configurations (Directory listing, etc.)."
  print "  -m, --max-amount-to-crawl             If you crawl, do it up to this amount of links for each web site. Defaults to 50."
  print "  -F, --download-files                  If you crawl, download every file to disk."
  print "  -c, --not-countrys                    Do not resolve the country name for every IP and hostname."
  print "  -C, --not-colors                      Do not use colored output."
  print "  -q, --not-spf                         Do not check SPF records."
  print "  -k, --random-domains                  Find this amount of domains from google and analyze them. For base domain use -d"
  print "  -v, --ignore-host-pattern             When using nmap to find active hosts and to port scan, ignore hosts which names match this pattern. Separete them with commas."
  print "  -x, --nmap-scantype                   Nmap parameters to port scan. Defaults to: '-O --reason --webxml --traceroute -sS -sV -sC -PN -n -v -F' ."
  print "  -b, --robtex-domains                  If we found a DNS server with zone transfer activated, search other UNrelated domains using that DNS server with robtex and analyze them too."
  print "  -B, --all-robtex                      Like -b, but also if no Zone Transfer was found. Useful to analyze all the domains in one corporative DNS server. Includes also -b."
  print "Press CTRL-C at any time to stop only the current step."
  print
  sys.exit(1)


def get_NS_records(domain):
    """
    This function takes the domain and ask for the nameservers information
    """
    global debug
    global domain_data
    global check_common_hosts_names
    global zone_transfer
    global net_block
    global output_file
    global output_directory
    global not_store_nmap
    global subdomains_found
    global not_subdomains
    global geoip_cache
    global output_file_handler
    global countrys

    hosttype={}
    reverseDNS={}
    hostname={}    
    ip_registry=[]


    #
    # Here we obtain the NS servers for the domain
    #
    try: 


        print '\tChecking NameServers using system default resolver...'
        if output_file!="":
            output_file_handler.writelines('\tChecking NameServers using system default resolver...\n')
        # Get the list of name servers IPs
        ns_servers = dns.resolver.query(domain, 'NS')

        if debug:
            logging.debug('\t\t> There are {0} nameservers'.format(len(ns_servers)))

        for rdata in ns_servers:

            if debug:
                logging.debug('\t\t> Looking for {0} IP address'.format(rdata.to_text()))
            # We search for the IP of each NSs    
            ip_list = dns.resolver.query(rdata.to_text()[:-1], 'A')
            # For each IP we store its information
            
            for ip in ip_list:
                ip_registry=[]
                if debug:
                    logging.debug('\t\t> NS IP: {0}'.format(ip.to_text()))

                try:
                    # If already exists this IP in the registry
                    # We search for this IP in the main dict 

                    ip_registry=domain_data['IpsInfo'][ip.to_text()]

                    # Here we store the hostname in a dictionary. The index is 'HostName'
                    hostname['HostName']=rdata.to_text()[:-1]
                    ip_registry.append(hostname)
                    # Here we store the type of register in a dictionary. The index is 'Type'
                    hosttype['Type']='NS'
                    ip_registry.append(hosttype)


                    # Do we have the country of this ip?
                    has_country=False
                    for dicts in ip_registry:
                        if dicts.has_key('IpCountry'):
                            has_country=True

                    if not has_country and countrys:
                        # We don't have this country
                        if debug:
                            logging.debug('\t\t> No country yet')
                        ipcountry={}
                        country=geoip_cache.country_name_by_addr(ip.to_text())
                        ipcountry['IpCountry']=country
                        ip_registry.append(ipcountry)
                        if debug:
                            logging.debug('\t\t> Country: {0}'.format(country))


                    # Obtain Ip's reverse DNS name if we don't have it
                    has_ptr=False
                    for dicts in ip_registry:
                        if dicts.has_key('PTR'):
                            has_ptr=True

                    if not has_ptr:
                        # Obtain Ip's reverse DNS name
                        reverse_name=check_PTR_record(ip.to_text())

                        if reverse_name != "":
                            reverseDNS['PTR']=reverse_name
                            ip_registry.append(reverseDNS)


                    # We store it in the main dictionary
                    a=[]
                    a=copy.deepcopy(ip_registry)
                    domain_data['IpsInfo'][ip.to_text()]=a

                    printout(domain,ip.to_text(),0)

                except KeyError:
                    # If this is a new IP
                    ip_registry=[]
                    ipcountry={}

                    # Do we have the country of this ip?
                    if countrys:
                        country=geoip_cache.country_name_by_addr(ip.to_text())
                        ipcountry['IpCountry']=country
                        ip_registry.append(ipcountry)

                    # Here we store the hostname in a dictionary. The index is 'HostName'
                    hostname['HostName']=rdata.to_text()[:-1]
                    ip_registry.append(hostname)
                    # Here we store the type of register in a dictionary. The index is 'Type'
                    hosttype['Type']='NS'
                    ip_registry.append(hosttype)

                    # Obtain Ip's reverse DNS name
                    reverse_name=check_PTR_record(ip.to_text())

                    if reverse_name != "":
                        reverseDNS['PTR']=reverse_name
                        ip_registry.append(reverseDNS)

                    # We store it in the main dictionary
                    a=[]
                    a=copy.deepcopy(ip_registry)
                    domain_data['IpsInfo'][ip.to_text()]=a

                    printout(domain,ip.to_text(),0)


    except Exception as inst:
        logging.warning('\t\tWARNING! It seems that the NS server does not have an IP!')
        if output_file!="":
            output_file_handler.writelines('\t\tWARNING! It seems that the NS server does not have an IP!\n')
        return -1
    except KeyboardInterrupt:
        try:
            # CTRL-C pretty handling.
            print "Keyboard Interruption!. Skiping the NS search step. Press CTRL-C again to exit."
            time.sleep(1)
            return (2)

        except KeyboardInterrupt:
            sys.exit(1)




def get_MX_records(domain):
    """
    This function takes the domain and ask for mailservers information
    """
    global debug
    global domain_data
    global check_common_hosts_names
    global zone_transfer
    global net_block
    global output_file
    global output_directory
    global not_store_nmap
    global subdomains_found
    global not_subdomains
    global geoip_cache
    global output_file_handler
    global countrys

    hosttype={}
    reverseDNS={}
    hostname={}    
    ip_registry=[]
    #
    # Here we obtain the MX servers for the domain
    #

    print '\n\tChecking MailServers using system default resolver...'
    if output_file!="":
        output_file_handler.writelines('\n\tChecking MailServers using system default resolver...\n')
    try:
        mail_servers = dns.resolver.query(domain, 'MX')
        for rdata in mail_servers:
            # We search for the IP of each NSs    
            ip_list = dns.resolver.query(rdata.exchange.to_text()[:-1], 'A')
            # For each IP we store its information
            for ip in ip_list:
                ip_registry=[]

                try:
                    # If already exists this IP in the registry
                    # We search for this IP in the main dict 
                    
                    ip_registry=domain_data['IpsInfo'][ip.to_text()]

                    # Here we store the hostname in a dictionary. The index is 'HostName'
                    hostname['HostName']=rdata.exchange.to_text()[:-1]
                    ip_registry.append(hostname)
                    # Here we store the type of register in a dictionary. The index is 'Type'
                    hosttype['Type']='MX'
                    ip_registry.append(hosttype)

                    # Do we have the country of this ip?
                    has_country=False
                    for dicts in ip_registry:
                        if dicts.has_key('IpCountry'):
                            has_country=True

                    if not has_country and countrys:
                        # We don't have this country
                        if debug:
                            logging.debug('\t\t> No country yet')
                        ipcountry={}
                        country=geoip_cache.country_name_by_addr(ip.to_text())
                        ipcountry['IpCountry']=country
                        ip_registry.append(ipcountry)
                        if debug:
                            logging.debug('\t\t> Country: {0}'.format(country))

                    # Obtain Ip's reverse DNS name if we don't have it
                    has_ptr=False
                    for dicts in ip_registry:
                        if dicts.has_key('PTR'):
                            has_ptr=True

                    if not has_ptr:
                        # Obtain Ip's reverse DNS name
                        reverse_name=check_PTR_record(ip.to_text())

                        if reverse_name != "":
                            reverseDNS['PTR']=reverse_name
                            ip_registry.append(reverseDNS)

                    # We store it in the main dictionary
                    a=[]
                    a=copy.deepcopy(ip_registry)
                    domain_data['IpsInfo'][ip.to_text()]=a

                    printout(domain,ip.to_text(),0)


                except KeyError:
                    # If this is a new IP
                    ip_registry=[]
                    ipcountry={}
            
                    if countrys:
                        # Do we have the country of this ip?
                        country=geoip_cache.country_name_by_addr(ip.to_text())
                        ipcountry['IpCountry']=country
                        ip_registry.append(ipcountry)
                        if debug:
                            logging.debug('\t\t> Country: {0}'.format(country))

                    # Here we store the hostname in a dictionary. The index is 'HostName'
                    hostname['HostName']=rdata.exchange.to_text()[:-1]
                    ip_registry.append(hostname)
                    # Here we store the type of register in a dictionary. The index is 'Type'
                    hosttype['Type']='MX'
                    ip_registry.append(hosttype)

                    # Obtain Ip's reverse DNS name
                    reverse_name=check_PTR_record(ip.to_text())

                    if reverse_name != "":
                        reverseDNS['PTR']=reverse_name
                        ip_registry.append(reverseDNS)

                    # We store it in the main dictionary
                    a=[]
                    a=copy.deepcopy(ip_registry)
                    domain_data['IpsInfo'][ip.to_text()]=a

                    printout(domain,ip.to_text(),0)

    except :
        logging.warning('\t\tWARNING!! There are no MX records for this domain')
        if output_file!="":
            output_file_handler.writelines('\t\tWARNING!! There are no MX records for this domain\n')
        return -1





def dns_request(domain):
    """
    This function takes the domain and ask for several related dns information
    """
    global debug
    global domain_data
    global check_common_hosts_names
    global use_common_list
    global common_list_path
    global zone_transfer
    global net_block
    global output_file
    global output_directory
    global not_store_nmap
    global subdomains_found
    global not_subdomains
    global common_hostnames
    global geoip_cache
    global output_file_handler
    global countrys

    try:
        hosttype={}
        reverseDNS={}
        hostname={}    
        ip_registry=[]


        if check_common_hosts_names==False:
            common_hostnames=[]
        

        elif use_common_list == True:
            common_hostnames=[]
            external_dns_file_name = os.path.join(os.getcwd(), common_list_path)
            ins = open ( external_dns_file_name , "r" )
            for line in ins:
                common_hostnames.append( line.rstrip() )
        else:
            common_hostnames=['www','ftp','vnc','fw','mail' ,'dba' ,'db' ,'mssql' ,'sql' ,'ib','secure','oracle' ,'ora' ,'oraweb' ,'sybase' ,'gw' ,'log' ,'logs' ,'logserver' ,'backup' ,'windows' ,'win' ,'nt' ,'ntserver' ,'win2k' ,'mswin' ,'msnt' ,'posnt' ,'server' ,'test' ,'firewall' ,'cp' ,'cpfw1' ,'cpfw1ng' ,'fw' ,'fw1' ,'raptor' ,'drag' ,'dragon' ,'pix' ,'ciscopix' ,'nameserver' ,'dns' ,'ns' ,'ns1' ,'ns2' ,'mx' ,'webmail' ,'mailhost' ,'smtp' ,'owa' ,'pop' ,'notes' ,'proxy' ,'squid' ,'imap' ,'www1' ,'www2' ,'www3' ,'corp' ,'corpmail' ,'print' ,'printer' ,'search' ,'telnet' ,'tftp' ,'web' ,'bgp' ,'citrix' ,'pcanywhere' ,'ts' ,'terminalserver' ,'tserv' ,'tserver' ,'keyserver' ,'pgp' ,'samba' ,'linux' ,'redhat' ,'caldera' ,'openlinux' ,'conectiva' ,'corel' ,'corelinux' ,'debian' ,'mandrake' ,'linuxppc' ,'bastille' ,'stampede' ,'suse' ,'trinux' ,'trustix' ,'turbolinux' ,'turbo' ,'tux' ,'slack' ,'slackware' ,'bsd' ,'daemon' ,'darby' ,'beasty' ,'beastie' ,'openbsd' ,'netbsd' ,'freebsd' ,'obsd' ,'fbsd' ,'nbsd' ,'solaris' ,'sun' ,'sun1' ,'sun2' ,'sun3' ,'aix' ,'tru64' ,'hp-ux' ,'hp' ,'lynx' ,'lynxos' ,'macosx' ,'osx' ,'minix' ,'next' ,'nextstep' ,'qnx' ,'rt' ,'sco' ,'xenix' ,'sunos' ,'ultrix' ,'unixware' ,'multics' ,'zeus' ,'apollo' ,'hercules' ,'venus' ,'pendragon' ,'guinnevere' ,'lancellot' ,'percival' ,'prometheus' ,'ssh' ,'time' ,'nicname' ,'tacacs' ,'domain' ,'whois' ,'bootps' ,'bootpc' ,'gopher' ,'http' ,'kerberos' ,'hostname' ,'pop2' ,'pop3' ,'nntp' ,'ntp' ,'irc' ,'imap3' ,'ldap' ,'https' ,'nntps' ,'ldaps' ,'webster' ,'imaps' ,'ircs' ,'pop3s' ,'login' ,'router' ,'netnews' ,'ica' ,'radius' ,'hsrp' ,'mysql' ,'amanda' ,'pgpkeyserver' ,'quake' ,'kerberos_master' ,'passwd_server' ,'smtps' ,'swat' ,'support' ,'afbackup' ,'postgres' ,'fax' ,'hylafax' ,'tircproxy' ,'webcache' ,'tproxy' ,'jetdirect' ,'kamanda' ,'fido','old']


        #
        # Here we obtain the NS servers for the domain
        #
        get_NS_records(domain)
        
        #
        # Here we obtain the MX servers for the domain
        #
        get_MX_records(domain)


        #
        # Here we check if wildcard is activated
        #
        try:
            wildcard_detect = dns.resolver.query('asdf80a98vrnwe9ufrcsajd90awe8ridsjkd.'+domain, 'A')
            logging.warning('\t\tWARNING!! This domain has wildcards activated for hostnames resolution. We are checking "www" anyway, but perhaps it doesn\'t exists!')
            if output_file!="":
                output_file_handler.writelines('\t\tWARNING!! This domain has wildcards activated for hostnames resolution. We are checking "www" anyway, but perhaps it doesn\'t exists!\n')
            
            # If wildcard is activated we don't check common hostnames except for www, it is too common not to be there!
            common_hostnames=['www']
        except:
            # If wildcard is not activated we check every hostname
            pass

    
        #
        # Here we check the zone transfer for each NS
        #

        if zone_transfer:
            print '\n\tChecking the zone transfer for each NS... (if this takes more than 10 seconds, just hit CTRL-C and it will continue. Bug in the libs)'
            if output_file!="":
                output_file_handler.writelines('\n\tChecking the zone transfer for each NS... (if this takes more than 10 seconds, just hit CTRL-C and it will continue. Bug in the libs)\n')
            try:
                name_servers_list=[]

                for ip in domain_data['IpsInfo']:
                    for dicts in domain_data['IpsInfo'][ip]:
                        if dicts.has_key('Type'):
                            if dicts['Type']=='NS':
                                name_servers_list.append(ip)

                if debug:
                    logging.debug('\t\t> Name server list: {0} '.format(name_servers_list))

                # For each nameserver we check the zone transfer
                for ip in name_servers_list:
                    try:
                        zone_transfer_data = dns.zone.from_xfr(dns.query.xfr(ip, domain,timeout=-1))
                        logging.critical('\t\tZone transfer successful on name server {0} ({1} hosts)'.format(ip, len(zone_transfer_data.items())))
                        if output_file!="":
                            output_file_handler.writelines('\t\tZone transfer successful on name server {0} ({1} hosts)\n'.format(ip, len(zone_transfer_data.items())))
                        # We should store this information in OS info or something...
                        ip_registry=[]
                        hosttype={}

                        try:
                            # If already exists this IP in the registry store it. ip is an IP. NS should
                            # be always stored!
                            ip_registry=domain_data['IpsInfo'][ip]

                            hosttype['ZT']=len(zone_transfer_data.items())
                            ip_registry.append(hosttype)
                            if debug:
                                logging.debug('\t\t> Storing ZT data for {0} : {1} hostnames: {2}'.format(ip,len(zone_transfer_data.items()),zone_transfer_data.keys()))
                            # We store it in the main dictionary
                            a=[]
                            a=copy.deepcopy(ip_registry)
                            domain_data['IpsInfo'][ip]=a
                        except:
                            if debug:
                                logging.warning('\t> WARNING! NS should be already stored in memory, and this one is not: {0}'.format(ip))

                        # If we found a zone transfer, we should not use the common_hostnames. It is enough with the zone! Thanks to Agustin Gugliotta
                        common_hostnames = [] 
                        for host in zone_transfer_data:
                            #if not(host in common_hostnames) and not('@' in host.to_text())and not ( '*' in host.to_text()):
                            common_hostnames.append(host.to_text())


                    except:
                        print '\t\tNo zone transfer found on nameserver {0}'.format(ip)
                        if output_file!="":
                            output_file_handler.writelines('\t\tNo zone transfer found on nameserver {0}\n'.format(ip))
            except KeyboardInterrupt:
                try:
                    # CTRL-C pretty handling.
                    print "Keyboard Interruption!. Skiping the zone transfer step. Press CTRL-C again to exit."
                    time.sleep(1)
                    return (2)

                except KeyboardInterrupt:
                    sys.exit(1)
            except:
                logging.warning('\t\tZone error?')
                pass
    

        #
        # Here we look for SPF record to obtain new IP address
        #
        check_SPF_record(domain)

        #
        # Here we check the A records of the hosts names, included de most common ones. 
        # This function is called BEFORE the nmap sL scan, so that we can include every netblock in the sL scan.
        #
        check_A_records(domain,'most common')
    

        #
        # Here we obtain the host names for each IP of every netblock using sL
        #
        if net_block:
            print '\n\tChecking with nmap the reverse DNS hostnames of every <ip>/24 netblock using system default resolver...'
            if output_file!="":
                output_file_handler.writelines('\n\tChecking with nmap the reverse DNS hostnames of every <ip>/24 netblock using system default resolver...\n')
            try: 
                # We already check the common hostnames, this is just for the ones found by nmap sL
                common_hostnames2=copy.deepcopy(common_hostnames)
                common_hostnames=[]
                # We remember which netblock we did resolve...
                netblocks_checked=[]

                # For each ip, nmap sL it
                for ip in domain_data['IpsInfo']:

                    # Obtain the net block
                    # from 1.2.3.4 -> ['1','2','3']
                    temp_ip_net_block=ip.split('.')[:-1]
                    # from ['1','2','3'] -> 1.2.3.0
                    temp_ip_net_block.append('0')
                    temp=""
                    for i in temp_ip_net_block:
                        temp=temp+'.'+i
                    ip_net_block=temp[1:]

                    # do not check twice the same netblock!
                    if ip_net_block not in netblocks_checked:

                        if output_directory==False or not_store_nmap == 1:
                            nmap_command_temp='nmap -sL -v '+ip_net_block+'/24' 
                        else:
                            try:
                                os.mkdir(output_directory+'/nmap')
                            except OSError:
                                pass
                            nmap_command_temp='nmap -sL -v '+ip_net_block+'/24 -oA '+output_directory+'/nmap/'+ip_net_block+'.sL'
                        print '\t\tChecking netblock {0}'.format(ip_net_block)
                        if output_file!="":
                            output_file_handler.writelines('\t\tChecking netblock {0}\n'.format(ip_net_block))
                        nmap_command=shlex.split(nmap_command_temp)
                        nmap_result_raw=Popen(nmap_command, stdout=PIPE).communicate()[0]
                        nmap_result=nmap_result_raw.split('\n')

                        netblocks_checked.append(ip_net_block)
                    else:
                        if debug:
                            logging.debug('\t\t> Netblock {0} already resolved'.format(ip_net_block))
                
                    # Analyzing results
                    found=False
                    for i in nmap_result:
                        if i.find(domain)!=-1:
                            net_hostname=i.split('for ')[1].split(' (')[0].split('.')[0]
                            ip=i.split('(')[1].split(')')[0]

                            # We should add here the reverse DNS name of the host and the IP to de list!!!

                            if not(net_hostname in common_hostnames2):
                                common_hostnames.append(net_hostname)
                                common_hostnames2.append(net_hostname)
                                if debug:
                                    logging.debug('\t\t\tNew host name {0} found in IP {1}'.format(net_hostname,ip))
                                found=True

                                # Add this IP to the main dictionary, with its PTR record found
                                try:
                                    # If already exists this IP in the registry
                                    # We search for this IP in the main dict 
                                    ip_registry=domain_data['IpsInfo'][ip]
                                    if debug:
                                        logging.debug('\t\t\t\tThe IP {1} was not new, adding {0} as PTR if it not there.'.format(net_hostname,ip))
                                    # Do we have the country of this ip?
                                    has_country=False
                                    for dicts in ip_registry:
                                        if dicts.has_key('IpCountry'):
                                            has_country=True

                                    if not has_country and countrys:
                                        # We don't have this country
                                        if debug:
                                            logging.debug('\t\t> No country yet')
                                        ipcountry={}
                                        country=geoip_cache.country_name_by_addr(ip.to_text())
                                        ipcountry['IpCountry']=country
                                        ip_registry.append(ipcountry)
                                        if debug:
                                            logging.debug('\t\t> Country: {0}'.format(country))

                                    # Obtain Ip's reverse DNS name if we don't have it
                                    has_ptr=False
                                    for dicts in ip_registry:
                                        if dicts.has_key('PTR'):
                                            has_ptr=True

                                    if not has_ptr:
                                        # Obtain Ip's reverse DNS name
                                        reverse_name=check_PTR_record(ip)

                                        if reverse_name != "":
                                            reverseDNS['PTR']=net_hostname+'.'+domain
                                            ip_registry.append(reverseDNS)

                                    # We store it in the main dictionary
                                    a=[]
                                    a=copy.deepcopy(ip_registry)
                                    domain_data['IpsInfo'][ip]=a

                                    printout(domain,ip,0)


                                except KeyError:
                                    # If this is a new IP
                                    ip_registry=[]
                                    ipcountry={}
                                    if debug:
                                        logging.debug('\t\t\t\tThe IP {1} was new, adding it, the country and {0} as PTR.'.format(net_hostname,ip))

                                    
                                    if countrys:
                                        # Do we have the country of this ip?
                                        country=geoip_cache.country_name_by_addr(ip)
                                        ipcountry['IpCountry']=country
                                        ip_registry.append(ipcountry)

                                    # Here we store the hostname in a dictionary. The index is 'HostName'
                                    reverseDNS['PTR']=net_hostname+'.'+domain
                                    ip_registry.append(reverseDNS)

                                    # We store it in the main dictionary
                                    a=[]
                                    a=copy.deepcopy(ip_registry)
                                    domain_data['IpsInfo'][ip]=a

                                    printout(domain,ip,0)



                #
                # Here we check the A records of the hosts names found with nmap sL only. This function is called AFTER the nmap sL 
                # scan, so that we can include every netblock in the sL scan.
                #

                # Before this, we should check that the host names found by sL does not repeat with the NS or MX!!
                if found:
                    check_A_records(domain,'sL')
            except KeyboardInterrupt:
                try:
                    # CTRL-C pretty handling.
                    print "Keyboard Interruption!. Skiping the netblock resolution step. Press CTRL-C again to exit."
                    time.sleep(1)
                    return (2)

                except KeyboardInterrupt:
                    sys.exit(1)
            except:
                pass


    except Exception as inst:
        print type(inst)     # the exception instance
        print inst.args      # arguments stored in .args
        print inst           # __str__ allows args to printed directly
        x, y = inst          # __getitem__ allows args to be unpacked directly
        print 'x =', x
        print 'y =', y



def check_PTR_record(ip):
    """
    This function takes one ip and ask for the dns PTR record information or reverse DNS hostname, and latter adds it to the main dictionary
    """
    global debug
    global domain_data

    try:
        if debug:
            logging.debug('\t\t> Checking {0} ip reverse DNS hostname'.format(ip))

        temp_ip=ip.split('.')
        temp_ip.reverse()
        reverse_ip=""
        for i in temp_ip:
            reverse_ip=reverse_ip+i+'.'
        reverse_ip=reverse_ip+'in-addr.arpa'
        reverse_name_result = dns.resolver.query(reverse_ip, 'PTR')

        for i in reverse_name_result:
            reverse_name=i.to_text()[:-1]
        return reverse_name


    except Exception as inst:
        return ""
        print type(inst)     # the exception instance
        print inst.args      # arguments stored in .args
        print inst           # __str__ allows args to printed directly



def check_SPF_record(domain):
    """
    This function looks for SPF record information in the domain and adds the hosts found to the main dictionary
    """
    global debug
    global domain_data
    global common_hostnames
    global check_spf
    global output_file
    global output_file_handler
    reverseDNS={}

    if check_spf:

        try:
            print'\n\tChecking SPF record...'
            if output_file!="":
                output_file_handler.writelines('\n\tChecking SPF record...\n')

            temp_spf = dns.resolver.query(domain, 'TXT')

            # For each spf record...
            for spf_record in temp_spf:

                if 'v=spf' in spf_record.to_text():
                    # We found a SPF record
                    if debug:
                        print '\t\t> SPf record found: {0}'.format(spf_record.to_text())

                    hosttype={}
                    ip_registry=[]

                    # Split it in parts
                    spf_record_splitted=spf_record.to_text().split()

                    # For each part of the spf record
                    for part in spf_record_splitted:
                        # Look for hostnames
                        if 'a:' in part:
                            # Extract new ip4 ips
                            hostname=part.split('a:')[1].split('.')[0]
                            logging.error('\t\tNew hostname found: {0}'.format(hostname))
                            if output_file!="":
                                output_file_handler.writelines('\t\tNew hostname found: {0}\n'.format(hostname))
                            # We found a hostname
                            common_hostnames.append(hostname)

                        # Look for includes
                        if 'include' in part:
                            # Extract new ip4 ips
                            spf_domain=part.split('include:')[1]
                            if debug:
                                logging.debug('\t\t> Included domain in SPF: {0}'.format(spf_domain))
                            check_SPF_record(spf_domain)
                        # Look for ip version 4 and 6 addresses
                        if 'ip' in part:
                            # Extract new ip4 ips
                            try: 
                                if '/' in part:
                                    logging.warning('\t\tWARNING! SPF record allows an entire network to send mails. Probably an ISP network. We are not going to check the entire network by now: {0}, but only the network IP'.format(part.split('ip4')[1].split()[0][1:]))
                                    if output_file!="":
                                        output_file_handler.writelines('\t\tWARNING! SPF record allows an entire network to send mails. Probably an ISP network. We are not going to check the entire network by now: {0}, but only the network IP\n'.format(part.split('ip4')[1].split()[0][1:]))
                                    ip=part.split('ip4')[1].split()[0][1:].split('/')[0]
                                else:
                                    if debug:
                                        logging.debug('\t\t SPF has a unique IP')
                                    ip=part.split('ip4')[1].split()[0][1:]
                                # We found a ip4 ip

                                try:
                                    # If already exists this IP in the registry
                                    ip_registry=domain_data['IpsInfo'][ip]

                                    hosttype['Type']='SPF'
                                    ip_registry.append(hosttype)
                                    # We store it in the main dictionary
                                    a=[]
                                    a=copy.deepcopy(ip_registry)
                                    domain_data['IpsInfo'][ip]=a


                                except KeyError:
                                    # If this is a new IP
                                    logging.error('\t\tNew IP found: {0}'.format(ip))
                                    if output_file!="":
                                        output_file_handler.writelines('\t\tNew IP found: {0}\n'.format(ip))
                                    ip_registry=[]

                                    hosttype['Type']='SPF'
                                    ip_registry.append(hosttype)

                                    a=[]
                                    a=copy.deepcopy(ip_registry)
                                    domain_data['IpsInfo'][ip]=a


                                    # Check the PTR record of this new IP
                                    reverse_name=check_PTR_record(ip)

                                    if reverse_name != "":
                                        reverseDNS['PTR']=reverse_name
                                        ip_registry.append(reverseDNS)

                            except:
                                # No ips in the SPF or ipv6 addresses
                                logging.error('\t\t\tThere are no IPv4 addresses in the SPF. Maybe IPv6.')
                                if output_file!="":
                                    output_file_handler.writelines('\t\t\tThere are no IPv4 addresses in the SPF. Maybe IPv6.\n')
                                continue
        except :    
            logging.error('\t\tNo SPF record')
            if output_file!="":
                output_file_handler.writelines('\t\tNo SPF record\n')







def check_A_records(domain,text=""):
    """
    This function takes the domain and ask for the dns A record information. Text is just to print out which hosts are we checking.
    """
    global debug
    global domain_data
    global check_common_hosts_names
    global zone_transfer
    global net_block
    global output_file
    global output_directory
    global not_store_nmap
    global subdomains_found
    global not_subdomains
    global common_hostnames
    global geoip_cache
    global output_file_handler
    global countrys

    try:
        hosttype={}
        hostname={}    
        ipcountry={}    
        ip_registry=[]
        reverseDNS={}
        first_ctrl_c=True


        #
        # Here we obtain the A records for the common host names using system default resolver
        #

        # Making unique values of common_hostname vector            
        unique_list=[]
        for i in common_hostnames:
            if i not in unique_list:
                unique_list.append(i)
        
        print '\n\tChecking {0} {1} hostnames using system default resolver...'.format(len(unique_list),text)
        if output_file!="":
            output_file_handler.writelines('\n\tChecking {0} {1} hostnames using system default resolver...\n'.format(len(unique_list),text))
        
        # For each of the host names    
        for common_host in unique_list:
            try:
                # We search host IP
                if debug:
                    logging.debug('\t> Checking {0} host'.format(common_host),)
                host_name_ips = dns.resolver.query(common_host+'.'+domain, 'A')



                #
                # We search if this host is in fact a subdomain
                #
                if not_subdomains==False:
                    try:
                        # If a host has a NS for its own, then we think its a subdomain
                        if debug:
                            logging.debug('\t\t> Checking if {0} is a subdomain...'.format(common_host),)
                        host_name_ns = dns.resolver.query(common_host+'.'+domain, 'NS')

                        # Almost sure it is a new subdomain. Now we confirm it. If it is not a CNAME, then it is really a subdomain and we add it
                        try:
                            host_name_cname = dns.resolver.query(common_host+'.'+domain, 'CNAME')

                        except:

                            # Here we avoid recursive domains!! for example the domain 'name' has this problem of
                            # recursive subdomains
                            # The idea is to avoid adding a subdomain if the previous 'subdomain' in the hostname is the same that the current one
                            # For example we avoid adding test.test.com

                            if common_host != domain.split('.')[0]:
                                # We add the new subdomain for later analysis 
                                ip_registry=[]
                                subdomain={}
                                for ip in host_name_ips:
                                    subdomain['SubDomain']=common_host+'.'+domain
                                    ip_registry.append(subdomain)
                                    # We store it in the main dictionary
                                    a=[]
                                    a=copy.deepcopy(ip_registry)
                                    domain_data['IpsInfo'][ip.to_text()]=a
                                ip_registry=[]
                                subdomain={}
                                for ip in host_name_ips:
                                    subdomain['SubDomain']=common_host+'.'+domain
                                    ip_registry.append(subdomain)
                                    # We store it in the main dictionary
                                    a=[]
                                    a=copy.deepcopy(ip_registry)
                                    domain_data['IpsInfo'][ip.to_text()]=a

                                subdomains_found.append(common_host+'.'+domain)

                            else:
                                logging.warning('\t\tWARNING! Recursive domains detected. Not adding them to the check list.')
                                if output_file!="":
                                    output_file_handler.writelines('\t\tWARNING! Recursive domains detected. Not adding them to the check list.\n')

                    except:
                        if debug:
                            logging.debug('\t\t> Host {0} is not a subdomain. Or its DNS is configured wrongly.'.format(common_host+'.'+domain))

            except KeyboardInterrupt:
                try:
                    # CTRL-C pretty handling.
                    print "Keyboard Interruption!. Skiping the hostname search step. Press CTRL-C quickly again to exit. Or wait 1 second and press CTRL-C again to continue."
                    time.sleep(1)
                    if first_ctrl_c == True:
                        first_ctrl_c=False
                        continue
                    elif first_ctrl_c == False:
                        return (2)


                except KeyboardInterrupt:
                    sys.exit(1)
            except:
                if debug:
                    logging.debug('\t\t> No ip found for {0} host'.format(common_host))
                continue

            # For each IP we store its information
            for ip in host_name_ips:
                ip_registry=[]
                hosttype={}

                try:

                    # We don't want to scan our own machine if some NS has 'localhost' in its database! It happens!!
                    if ip.to_text().find('127.') != 0:

                        # If already exists this IP in the registry
                        ip_registry=domain_data['IpsInfo'][ip.to_text()]


                        # Do we have the country of this ip?
                        has_country=False
                        for dicts in ip_registry:
                            if dicts.has_key('IpCountry'):
                                has_country=True

                        if not has_country and countrys:
                            # We don't have this country
                            if debug:
                                logging.debug('\t\t> No country yet')
                            country=geoip_cache.country_name_by_addr(ip.to_text())
                            ipcountry['IpCountry']=country
                            ip_registry.append(ipcountry)
                            if debug:
                                logging.debug('\t\t> Country: {0}'.format(country))

                        # Here we store the hostname in a dictionary. The index is 'HostName'
                        hostname['HostName']=common_host+'.'+domain
                        ip_registry.append(hostname)
                        # Here we store the type of register in a dictionary. The index is 'Type'
                        hosttype['Type']='A'
                        ip_registry.append(hosttype)

                        # Obtain Ip's reverse DNS name if we don't have it
                        has_ptr=False
                        for dicts in ip_registry:
                            if dicts.has_key('PTR'):
                                has_ptr=True

                        if not has_ptr:
                            reverse_name=check_PTR_record(ip.to_text())

                            if reverse_name != "":
                                reverseDNS['PTR']=reverse_name
                                ip_registry.append(reverseDNS)

                        # We store it in the main dictionary
                        a=[]
                        a=copy.deepcopy(ip_registry)
                        domain_data['IpsInfo'][ip.to_text()]=a

                        printout(domain,ip.to_text(),0)


                except KeyError:
                    # If this is a new IP
                    ip_registry=[]

                    if countrys:
                        # Search the country of the IP
                        country=geoip_cache.country_name_by_addr(ip.to_text())
                        ipcountry['IpCountry']=country
                        ip_registry.append(ipcountry)

                    # Here we store the hostname in a dictionary. The index is 'HostName'
                    hostname['HostName']=common_host+'.'+domain
                    ip_registry.append(hostname)
                    # Here we store the type of register in a dictionary. The index is 'Type'
                    hosttype['Type']='A'
                    ip_registry.append(hosttype)

                    # We store it in the main dictionary
                    a=[]
                    a=copy.deepcopy(ip_registry)
                    domain_data['IpsInfo'][ip.to_text()]=a

                    printout(domain,ip.to_text(),0)
                except KeyboardInterrupt:
                    try:
                        # CTRL-C pretty handling.
                        print "Keyboard Interruption!. Skiping IP resolution step. Press CTRL-C again to exit."
                        time.sleep(1)
                        return (2)

                    except KeyboardInterrupt:
                        sys.exit(1)


    except Exception as inst:
        print type(inst)     # the exception instance
        print inst.args      # arguments stored in .args
        print inst           # __str__ allows args to printed directly

    except KeyboardInterrupt:
        try:
            # CTRL-C pretty handling.
            print "Keyboard Interruption!. Skiping entire step. Press CTRL-C again to exit."
            time.sleep(1)
            return (2)

        except KeyboardInterrupt:
            sys.exit(1)


def find_and_analyze_random_domains(domain, amount):
    """
    This function find X random domain names in internet. You can choose which country do you want them from. Each domain is analyzed after it is found
    and before the next domain is searched, so we do not strees the google web search.
    """
    global debug
    global domain_data
    global output_file
    global output_file_handler

    try:
        import string
        import httplib
        import urllib2
        import re
        import random
        domain_dict={}
        counter=-1
        uniq_domains_web=""
        logging.info('\tFinding {0} pseudo-random sub-domains to analyze in the {1} domain.\n'.format(amount,domain))
        if output_file!="":
            output_file_handler.writelines('\tFinding {0} pseudo-random sub-domains to analyze in the {1} domain.\n'.format(amount,domain))


        # Extract the first dot if it exist
        if domain[0]=='.':
            domain=domain[1:]

        # Add slashes before every dot
        domain_re=domain.replace('.','\.')
        

        # Initialize random seed
        random.seed()

        final_dict={}
        while amount:
            # We search in the first 100 pages
            page_counter_web = random.randrange(1,100,10)
            try:
                results_web = 'http://www.google.com/search?q=inurl%3a'+str(domain)+'&hl=en&btnG=Search&aq=f&start='+ repr(page_counter_web) + '&sa=N'
                request_web = urllib2.Request(results_web)
                request_web.add_header('User-Agent','Mozilla/4.0 (compatible;MSIE 5.5; Windows NT 5.0)')
                opener_web = urllib2.build_opener()
                text = opener_web.open(request_web).read()
        
                # This re extracts the domains
                domains_web = (re.findall('(http:\/\/\w[\w\.\-]+\.'+domain_re+')',text))

                if debug:
                    print '\tDomains: {0}'.format(domains_web)

                # For every domain found, we store them in a dictionary
                for dom_web in domains_web:
                    # 0 means not-analyzed    
                    try:
                        # If it already existed... leave it
                        test_domain=domain_dict[dom_web]
                    except:
                        # If it does not existed, store it
                        domain_dict[dom_web]=5

                if debug:
                    logging.debug('\tInformation found so far: {0}'.format(domain_dict))

                # Warn about google limits...
                if domain_dict == {}:
                    logging.warning('\tWARNING! Something prevent us from obtaining results from google. Try again the same command until it succeed. If it does not work (because you use this feature many times) google could have blocked you for five minutes or so.')
                    if output_file!="":
                        output_file_handler.writelines('\tWARNING! Something prevent us from obtaining results from google. Try again the same command until it succeed1. If it does not work (because you use this feature many times) google could have blocked you for five minutes or so.\n')
                    return -1

                
                # For every domain found, verify it.
                for uniq_domains_web in domain_dict.keys():
                    if 'http://' in uniq_domains_web:
                        temp=uniq_domains_web
                        uniq_domains_web=temp[temp.index('http://')+7:]
                    if 'www' in uniq_domains_web:
                        temp=uniq_domains_web
                        uniq_domains_web=temp[temp.index('www')+4:]

                    # This is to avoid finding exactly the base directory... is this right?? why not domain==uniq_domains_web?
                    if len(domain) == len(uniq_domains_web):
                        continue

                    ## Do not get hostnames but its domains...
                    ## If we found 'aa.bb.cc.dd' we end with 'bb.cc.dd'
                    #temp=uniq_domains_web
                    #temp2=temp.split('.')[2:]
                    #temp3=temp.split('.')[1]
                    #for i in temp2:
                        #temp3=temp3+'.'+i
#
                    #uniq_domains_web=temp3
#
                    #if debug:
                        #logging.debug('\t> We found the hostname {0}, extracting its domain: {1}'.format(temp, uniq_domains_web))


                    try:
                        # is it there? do not add it
                        temp_final=final_dict[uniq_domains_web]
                    except:
                        # Store it
                        # 0 means not-analyzed    
                        final_dict[uniq_domains_web]=0

                if final_dict == []:
                    print '\tNo more domains found'
                    if output_file!="":
                        output_file_handler.writelines('\tNo more domains found\n')
                    return (1)


                # How much domains we got?
                counter=len(final_dict.keys())

                logging.info('\tWe found these domains in this first search:')
                if output_file!="":
                    output_file_handler.writelines('\tWe found these domains in this first search:\n')
                    
                for i in final_dict:
                    logging.info('\t\t{0}'.format(i))
                    if output_file!="":
                        output_file_handler.writelines('\t\t{0}\n'.format(i))

                for i in final_dict:
                    if debug:
                        logging.debug('\t> Domain to analyze next: {0} in {1}. Amount={2}'.format(i,final_dict, amount))

                    # If we still have to check domains...
                    if amount:
                        # 0 means 'ready to analyze', and 1 means 'already analyzed'
                        if final_dict[i]==0:
                            analyze_domain(i)
                            final_dict[i]=1
                        amount = amount - 1
                        if debug:
                            logging.debug('\t\tDomains analyzed so far: {0}'.format(final_dict))
                print '3'


            except Exception as inst:
                print type(inst)     # the exception instance
                print inst.args      # arguments stored in .args
                print inst           # __str__ allows args to printed directly

            except IOError:
                logging.error('\t> Can\'t connect to Google Web! maybe the page number {0} does not exist?'.format(page_counter_web))
                if output_file!="":
                    output_file_handler.writelines('\t> Can\'t connect to Google Web! maybe the page number {0} does not exist?'.format(page_counter_web))



    except Exception as inst:
        print type(inst)     # the exception instance
        print inst.args      # arguments stored in .args
        print inst           # __str__ allows args to printed directly




def check_domain_emails(domain):
    """
    This function implements the goog-mail.py program that was once included in backtrack 2. We don't know who the author was but we thanks him/her and 
    we give him/her the credit for it
    """
    global debug
    global domain_data
    global output_file
    global output_file_handler

    def StripTags(text):
        finished = 0
        while not finished:
            finished = 1
            start = text.find("<")
            if start >= 0:
                stop = text[start:].find(">")
                if stop >= 0:
                    text = text[:start] + text[start+stop+1:]
                    finished = 0
        return text
    try:
        import string
        import httplib
        import urllib2
        import re
        print '\n\tSearching for {0} emails in Google'.format(domain)
        if output_file!="":
            output_file_handler.writelines('\n\tSearching for {0} emails in Google\n'.format(domain))
        d={}
        page_counter = 0
        try:
            while page_counter < 50 :
                results = 'http://groups.google.com/groups?q='+str(domain)+'&hl=en&lr=&ie=UTF-8&start=' + repr(page_counter) + '&sa=N'
                request = urllib2.Request(results)
                request.add_header('User-Agent','Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.0)')
                opener = urllib2.build_opener()
                text = opener.open(request).read()
                emails = (re.findall('([\w\.\-]+@'+domain+')',StripTags(text)))
                for email in emails:
                    d[email]=1
                    uniq_emails=d.keys()
                page_counter = page_counter + 10
        except IOError:
            logging.debug("\t> Can't connect to Google Groups!"+"")
        page_counter_web=0
        try:
            while page_counter_web < 50 :
                results_web = 'http://www.google.com/search?q=%40'+str(domain)+'&hl=en&lr=&ie=UTF-8&start='+ repr(page_counter_web) + '&sa=N'
                request_web = urllib2.Request(results_web)
                request_web.add_header('User-Agent','Mozilla/4.0 (compatible;MSIE 5.5; Windows NT 5.0)')
                opener_web = urllib2.build_opener()
                text = opener_web.open(request_web).read()
                emails_web = (re.findall('([\w\.\-]+@'+domain+')',StripTags(text)))
                for email_web in emails_web:
                    d[email_web]=1
                    uniq_emails_web=d.keys()
                page_counter_web = page_counter_web + 10
        except IOError:
            logging.debug("\t> Can't connect to Google Web!"+"")
        for uniq_emails_web in d.keys():
            # Just adds a warning if the emails is more thatn 20 characters long. Not in the original goog-mail.py
            if len(uniq_emails_web.split('@')[0]) >= 20:
                uniq_emails_web_temp=uniq_emails_web
                uniq_emails_web=uniq_emails_web_temp+' - Is this real?'
            logging.warning('\t\t'+uniq_emails_web)
            if output_file!="":
                output_file_handler.writelines('\t\t'+uniq_emails_web)
            domain_registry=[]
            email_list={}
            # If already exists this IP in the registry
            domain_registry=domain_data['DomainInfo']
            # Here we store the email obtained in a dictionary. The index is 'Email'
            email_list['Email']=uniq_emails_web
            domain_registry.append(email_list)
            if debug:
                logging.debug('\t\t> Emails found so far : {0}'.format(domain_registry))
            # We store it in the main dictionary
            a=[]
            a=copy.deepcopy(domain_registry)
            domain_data['DomainInfo']=a
    except Exception as inst:
        print type(inst)     # the exception instance
        print inst.args      # arguments stored in .args
        print inst           # __str__ allows args to printed directly
        x, y = inst          # __getitem__ allows args to be unpacked directly
        print 'x =', x
        print 'y =', y
    except KeyboardInterrupt:
        try:
            # CTRL-C pretty handling.
            print "Keyboard Interruption!. Skiping the mail check step. Press CTRL-C again to exit."
            time.sleep(1)
            return (2)
        except KeyboardInterrupt:
            sys.exit(1)

def check_active_host():
    """
    This function check if hosts are up using nmap
    """
    global debug
    global domain_data
    global output_directory
    global output_file
    global output_file_handler
    global ignore_host_pattern
    hostup={}
    print '\n\tChecking {0} active hosts using nmap... (nmap -sn -n -v -PP -PM -PS80,25 -PA -PY -PU53,40125 -PE --reason <ip> -oA <output_directory>/nmap/<ip>.sn)'.format(len(domain_data['IpsInfo']))
    if output_file!="":
        output_file_handler.writelines('\n\tChecking {0} active hosts using nmap... (nmap -sn -n -v -PP -PM -PS80,25 -PA -PY -PU53,40125 -PE --reason <ip> -oA <output_directory>/nmap/<ip>.sn)\n'.format(len(domain_data['IpsInfo'])))
    try:
        # For each ip, nmap it
        for ip in domain_data['IpsInfo']:
            ignore=False
            ip_registry=domain_data['IpsInfo'][ip]
            reason=""
            # If any of the host names has the 'ignored' pattern, do not check it!
            if ignore_host_pattern:
                for dict in ip_registry:
                    for i in dict.keys():
                        if i == 'HostName':
                            for pattern in ignore_host_pattern.split(','):
                                if pattern in dict['HostName']:
                                    ignore=True
                                    print'\t\tPattern: {0}, Hostname: {1}. Ignoring!'.format(pattern,dict['HostName'])
                                    break
            if not ignore:
                # If no output directory was selected, do not store nmap output
                if output_directory==False or not_store_nmap == 1:
                    nmap_command_temp='nmap -sn -n -v -PP -PM -PS80,25 -PA -PY -PU53,40125 -PE --reason ' + ip
                else:
                    try:
                        os.mkdir(output_directory+'/nmap')
                    except OSError:
                        pass
                    nmap_command_temp = 'nmap -sn -n -v -PP -PM -PS80,25 -PA -PY -PU53,40125 -PE --reason '+ip+' -oA '+output_directory+'/nmap/'+ip+'.sn'
                nmap_command=shlex.split(nmap_command_temp)
                nmap_result=Popen(nmap_command, stdout=PIPE).communicate()[0]
                if nmap_result.find('Host is up, received')!=-1:
                    reason=nmap_result.split('received ')[1].split(' (')[0]
                    hostup['HostUp']='True ('+reason+')'
                    ip_registry.append(hostup)
                    # We store it in the main dictionary
                    a=[]
                    a=copy.deepcopy(ip_registry)
                    domain_data['IpsInfo'][ip]=a
                    logging.debug('\t\tHost {0} is up ({1})'.format(ip,reason))
                    if output_file!="":
                        output_file_handler.writelines('\t\tHost {0} is up ({1})\n'.format(ip,reason))
                else:
                    hostup['HostUp']="False"
                    ip_registry.append(hostup)
                    # We store it in the main dictionary
                    a=[]
                    a=copy.deepcopy(ip_registry)
                    domain_data['IpsInfo'][ip]=a
                    print '\t\tHost {0} is down'.format(ip)
                    if output_file!="":
                        output_file_handler.writelines('\t\tHost {0} is down\n'.format(ip))
    except Exception as inst:
        print type(inst)     # the exception instance
        print inst.args      # arguments stored in .args
        print inst           # __str__ allows args to printed directly
        x, y = inst          # __getitem__ allows args to be unpacked directly
        print 'x =', x
        print 'y =', y
    except KeyboardInterrupt:
        try:
            # CTRL-C pretty handling.
            print "Keyboard Interruption!. Skiping the active hosts test step. Press CTRL-C again to exit."
            time.sleep(1)
            return (2)
        except KeyboardInterrupt:
            sys.exit(1)


def host_info(domain):
    """
    This function checks open ports in the host and a lot of info about its SO
    """
    global debug
    global domain_data
    global nmap_scantype
    global nmap
    global output_directory
    global zenmap
    global output_file
    global output_file_handler
    print '\n\tChecking ports on every active host using nmap... (nmap '+nmap_scantype+' <ip> -oA <output_directory>/nmap/<ip>)'
    if output_file!="":
        output_file_handler.writelines('\n\tChecking ports on every active host using nmap... (nmap '+nmap_scantype+'  <ip> -oA <output_directory>/nmap/<ip>)\n')
    try:
        # For each ip, nmap it
        for ip in domain_data['IpsInfo']:
            if debug:
                logging.debug('\t\tChecking ip {0}'.format(ip))
            hostports={}
            scriptinfo={}
            hostos={}
            ip_registry=domain_data['IpsInfo'][ip]
            host_name=""
            try:
                # First read the variables...
                for dicts in ip_registry:
                    if dicts.has_key('PTR'):
                        host_name_temp=dicts.get('PTR')
                        host_name=host_name_temp+' (PTR)'
                    elif dicts.has_key('HostName'):
                        host_name=dicts.get('HostName')
                    if dicts.has_key('HostUp'):
                        # Only scan active hosts
                        if 'True' in dicts['HostUp']:
                            print '\t\tScanning ip {0} ({1}):'.format(ip,host_name)
                            if output_file!="":
                                output_file_handler.writelines('\t\tScanning ip {0} ({1}):\n'.format(ip,host_name))

                            # If no output directory was selected, do not store nmap output
                            if output_directory==False or not_store_nmap == 1:
                                    nmap_command_temp='nmap '+nmap_scantype+' ' + ip 
                            else:
                                try:
                                    os.mkdir(output_directory+'/nmap')
                                except OSError:
                                    nmap_command_temp='nmap '+nmap_scantype+' ' + ip + ' -oA '+output_directory+'/nmap/'+ip
                            # Do the nmap
                            nmap_command=shlex.split(nmap_command_temp)
                            nmap_result_raw=Popen(nmap_command, stdout=PIPE).communicate()[0]
                            nmap_result=nmap_result_raw.split('\n')
                            #
                            # Now analyze nmaps output
                            # Searching for ports, service and scripts info
                            starttoread_port_section=0
                            starttoread_traceroute_section=0
                            for line in nmap_result:
                                # Learning port information
                                # If we find the PORT word, we can start to analyze ports...
                                if line.find('PORT') != -1:
                                    starttoread_port_section = 1
                                    continue
                                # While we can learn ports but output did not finish
                                if starttoread_port_section==1 and 'Read data' not in line and 'Warning' not in line:
                                    if debug:
                                        logging.debug('\t\t\t> Line readed from nmap_result: {0}'.format(line))
                                    critical=True
                                    if ('tcp' in line or 'udp' in line) and 'open' in line:
                                        # Print information about the port
                                        # Try to find critical ports
                                        for cport in normal_port_list:
                                            if line.find(cport) == 0:
                                                critical=False
                                        if critical:
                                            logging.error('\t\t\t{0}'.format(line))
                                        else:
                                            logging.warning('\t\t\t{0}'.format(line))
                                        if output_file!="":
                                            output_file_handler.writelines('\t\t\t{0}\n'.format(line))
                                        # Store the port info 
                                        hostports['PortInfo']=line
                                        b={}
                                        b=copy.deepcopy(hostports)    
                                        ip_registry.append(b)
                                        # We store it in the main dictionary
                                        a=[]
                                        a=copy.deepcopy(ip_registry)
                                        domain_data['IpsInfo'][ip]=a
                                    # Are we yet in the script section?
                                    elif '|' in line:
                                        if debug:
                                            logging.info('\t\t\t> Script Line readed from nmap_result: {0}'.format(line))
                                        if critical:
                                            logging.error('\t\t\t\t{0}'.format(line))
                                            if output_file!="":
                                                output_file_handler.writelines('\t\t\t\t{0}\n'.format(line))
                                        else:
                                            logging.warning('\t\t\t\t{0}'.format(line))
                                            if output_file!="":
                                                output_file_handler.writelines('\t\t\t\t{0}\n'.format(line))
                                        scriptinfo['ScriptInfo']=line
                                        b={}
                                        b=copy.deepcopy(scriptinfo)    
                                        ip_registry.append(b)
                                        # We store it in the main dictionary
                                        a=[]
                                        a=copy.deepcopy(ip_registry)
                                        domain_data['IpsInfo'][ip]=a
                                # Only to extract the os?
                                if line.find('Service Info')!=-1:
                                    logging.warning('\t\t\tOS Info: {0}'.format(line))
                                    if output_file!="":
                                        output_file_handler.writelines('\t\t\tOS Info: {0}\n'.format(line))
                                    hostos['OsInfo']=line.split('Service Info:')[1]
                                    b={}
                                    b=copy.deepcopy(hostos)    
                                    ip_registry.append(b)
                                    # We store it in the main dictionary
                                    a=copy.deepcopy(ip_registry)
                                    domain_data['IpsInfo'][ip]=a
                                # traceroute
                                if 'TRACEROUTE' in line:
                                    starttoread_port_section=0
                                    starttoread_traceroute_section=1
                                    traceline=""
                                if starttoread_traceroute_section==1 and 'Read data' not in line and 'Warning' not in line and line != '':
                                    previoustraceline=traceline
                                    traceline=line
                                if 'Read data' in line or 'unrecognized' in line:
                                    starttoread_port_section=0
                                    starttoread_traceroute_section=0
                        host_name=dicts.get('HostName')
            except KeyboardInterrupt:
                try:
                    # CTRL-C pretty handling.
                    print "Keyboard Interruption!. Skiping this IP, going to the next.... Press CTRL-C again to move to the next check."
                    time.sleep(1)
                    continue
                except KeyboardInterrupt:
                    try:
                        # CTRL-C pretty handling.
                        print "Keyboard Interruption!. Skiping port scanning section. Press CTRL-C again to exit."
                        time.sleep(1)
                        return(1)
                    except KeyboardInterrupt:
                        sys.exit(1)
        # End for    
    except Exception as inst:
        print type(inst)     # the exception instance
        print inst.args      # arguments stored in .args
        print inst           # __str__ allows args to printed directly
        x, y = inst          # __getitem__ allows args to be unpacked directly
        print 'x =', x
        print 'y =', y
    except KeyboardInterrupt:
        try:
            # CTRL-C pretty handling.
            print "Keyboard Interruption!. Skiping the port scanning step. Press CTRL-C again to exit."
            time.sleep(1)
            return (2)

        except KeyboardInterrupt:
            sys.exit(1)

def tt():
    print "               !         !              \n              ! !       ! !              \n             ! . !     ! . !              \n                ^^^^^^^^^ ^                \n              ^             ^              \n            ^  (0)       (0)  ^           \n           ^        ""         ^           \n          ^   ***************    ^         \n        ^   *                 *   ^        \n       ^   *   /\   /\   /\    *    ^       \n      ^   *                     *    ^    \n     ^   *   /\   /\   /\   /\   *    ^    \n    ^   *                         *    ^    \n    ^  *                           *   ^    \n    ^  *                           *   ^    \n     ^ *                           *  ^     \n      ^*                           * ^     \n       ^ *                        * ^    \n       ^  *                      *  ^    \n         ^  *       ) (         * ^    \n             ^^^^^^^^ ^^^^^^^^^             \n                   Totoro              \n" 

def printout(domain,ip,option):
    """
    This function prints the domain information obtained
    """
    global debug
    global domain_data
    global output_file
    global output_directory
    global create_pdf
    global output_file_handler
    ip_vect=[]
    try:
        
        # If option = 1 we print all the data extracted
        if option==1:
            logging.debug('--Finished--')
            logging.info('Summary information for domain '+domain)
            logging.info('-----------------------------------------')

            # We store information for statistics 

            if output_directory!=False:
                output_file_handler.writelines('\n\n--Finished--\n')
                output_file_handler.writelines('Summary information for domain '+domain+'\n')
                output_file_handler.writelines('-----------------------------------------\n')
            
            # Print information for the domain first
            if len(domain_data['DomainInfo'])!=0:

                print '\tDomain Specific Information:'
                if output_file!="":
                    output_file_handler.writelines('\tDomain Specific Information:\n')

                for domdata in domain_data['DomainInfo']:
                    # We print the emails found for this domain
                    if domdata.has_key('Email'):
                        logging.warning('\t\tEmail: {0}'.format(domdata['Email']))
                        if output_file!="":
                            output_file_handler.writelines('\t\tEmail: {0}\n'.format(domdata.get('Email')))


            print '\n\tDomain Ips Information:'
            if output_file!="":
                output_file_handler.writelines('\n\tDomain Ips Information:\n')
        

            # For each IP in the main dictionary
            for ip in domain_data['IpsInfo']:
                hostname=""
                # We extract its vector
                ip_vect=domain_data['IpsInfo'][ip]
                logging.debug('\t\tIP: {0}'.format(ip))
                if output_file!="":
                    output_file_handler.writelines('\t\tIP: {0}\n'.format(ip))
                # These things are many times for ip
                for dicts in ip_vect:
                    if dicts.has_key('PTR'):
                        if dicts.get('PTR') != hostname:
                            logging.warning('\t\t\tHostName: {0}\t\t\tType: PTR'.format(dicts.get('PTR')))
                            if output_file!="":
                                output_file_handler.writelines('\t\t\tHostName: {0}\t\t\tType: PTR\n'.format(dicts.get('PTR')))
                        else:
                            print '\t\t\tHostName: {0}\t\t\tType: PTR'.format(dicts.get('PTR'))
                            if output_file!="":
                                output_file_handler.writelines('\t\t\tHostName: {0}\t\t\tType: PTR\n'.format(dicts.get('PTR')))
                    if dicts.has_key('HostName'):
                        print '\t\t\tHostName: {0}'.format(dicts.get('HostName')),
                        hostname=dicts.get('HostName')
                        if output_file!="":
                            output_file_handler.writelines('\t\t\tHostName: {0}'.format(dicts.get('HostName')))
                    if dicts.has_key('Type'):
                        print '\t\t\tType: {0}'.format(dicts.get('Type'))
                        if output_file!="":
                            output_file_handler.writelines('\t\t\tType: {0}\n'.format(dicts.get('Type')))
                    if dicts.has_key('SubDomain'):
                        logging.error('\t\t\tSub Domain: {0}'.format(dicts['SubDomain']))
                        if output_file!="":
                            output_file_handler.writelines('\t\t\tSub Domain: {0}\n'.format(dicts.get('SubDomain')))

                # These things are just once for ip
                for dicts in ip_vect:
                    if dicts.has_key('IpCountry'):
                        logging.info('\t\t\tCountry: {0}'.format(dicts.get('IpCountry')))
                        if output_file!="":
                            output_file_handler.writelines('\t\t\tCountry: {0}\n'.format(dicts.get('IpCountry')))
                    if dicts.has_key('HostUp'):
                        logging.info('\t\t\tIs Active: {0}'.format(dicts.get('HostUp')))
                        if output_file!="":
                            output_file_handler.writelines('\t\t\tIs Active: {0}\n'.format(dicts.get('HostUp')))
                    if dicts.has_key('PortInfo'):
                        # Try to find critical ports
                        critical=True
                        for cport in normal_port_list:
                            if dicts.get('PortInfo').find(cport) == 0:
                                critical=False

                        if critical:
                            logging.error('\t\t\tPort: {0}'.format(dicts.get('PortInfo')))
                            if output_file!="":
                                output_file_handler.writelines('\t\t\tPort: {0}\n'.format(dicts.get('PortInfo')))
                        else:
                            logging.warning('\t\t\tPort: {0}'.format(dicts.get('PortInfo')))
                            if output_file!="":
                                output_file_handler.writelines('\t\t\tPort: {0}\n'.format(dicts.get('PortInfo')))

                    if dicts.has_key('ScriptInfo'):
                        print '\t\t\t\tScript Info: {0}'.format(dicts.get('ScriptInfo'))
                        if output_file!="":
                            output_file_handler.writelines('\t\t\t\tScript Info: {0}\n'.format(dicts.get('ScriptInfo')))

                    if dicts.has_key('OsInfo'):
                        print '\t\t\tOs Info: {0}'.format(dicts.get('OsInfo'))
                        if output_file!="":
                            output_file_handler.writelines('\t\t\tOs Info: {0}\n'.format(dicts.get('OsInfo')))
                    if dicts.has_key('ZT'):
                        logging.critical('\t\t\tZone Transfer: {0}'.format(dicts.get('ZT')))
                        if output_file!="":
                            output_file_handler.writelines('\t\t\tZone Transfer: {0}\n'.format(dicts.get('ZT')))
                    if dicts.has_key('DirIndex'):
                        logging.critical('\t\t\tOpen Folders: {0}'.format(dicts.get('DirIndex')))
                        if output_file!="":
                            output_file_handler.writelines('\t\t\tOpen Folders: {0}\n'.format(dicts.get('DirIndex')))
            print
            logging.info('--------------End Summary --------------')
            logging.info('-----------------------------------------')
            if output_directory!=False:
                output_file_handler.writelines('\n--------------End Summary --------------\n')
                output_file_handler.writelines('-----------------------------------------\n')
            print '\n'
            if output_file != "":
                output_file_handler.writelines('\n')
            if output_file != "" and create_pdf != False:
                try:
                    print '\tCreating pdf file from {0} text output '.format(output_file)
                    os.system('/usr/bin/pyText2pdf.py ' + output_file)
                except OSError:
                    logging.warning('Warning! pyText2pdf.py not found. Please download from http://code.activestate.com/recipes/532908-text-to-pdf-converter-rewrite/download/1/')
        # If option != 1 we print all the data extracted until now
        else:
            # For each IP in the main dictionary
            ip_vect=domain_data['IpsInfo'][ip]
            # Things that are once per IP
            if countrys:
                for dicts in ip_vect:
                    if dicts.has_key('IpCountry'):
                        country=dicts.get('IpCountry')
    
                logging.info('\t\tIP: {0} ({1})'.format(ip,country))
                if output_file!="":
                    output_file_handler.writelines('\t\tIP: {0} ({1})\n'.format(ip,country))
            # Things that are multiple times per IP
            hostname=""
            for dicts in ip_vect:
                if dicts.has_key('PTR'):
                    if dicts.get('PTR') != hostname:
                        logging.warning('\t\t\tHostName: {0}\t\t\tType: PTR'.format(dicts.get('PTR')))
                        if output_file!="":
                            output_file_handler.writelines('\t\t\tHostName: {0}\t\t\tType: PTR\n'.format(dicts.get('PTR')))
                    else:
                        print '\t\t\tHostName: {0}\t\t\tType: PTR'.format(dicts.get('PTR'))
                        if output_file!="":
                            output_file_handler.writelines('\t\t\tHostName: {0}\t\t\tType: PTR\n'.format(dicts.get('PTR')))
                if dicts.has_key('Type'):
                    print '\t\t\tType: {0}'.format(dicts.get('Type'))
                    if output_file!="":
                        output_file_handler.writelines('\t\t\tType: {0}\n'.format(dicts.get('Type')))
                if dicts.has_key('HostName'):
                    hostname=dicts.get('HostName')
                    print '\t\t\tHostName: {0}'.format(dicts.get('HostName')),
                    if output_file!="":
                        output_file_handler.writelines('\t\t\tHostName: {0}'.format(dicts.get('HostName')))
                if dicts.has_key('SubDomain'):
                    logging.error('\t\t\tSub Domain: {0} <- New Subdomain!'.format(dicts['SubDomain']))
                    if output_file!="":
                        output_file_handler.writelines('\t\t\tSub Domain: {0} <- New Subdomain!\n'.format(dicts['SubDomain']))
    except Exception as inst:
        print type(inst)     # the exception instance
        print inst.args      # arguments stored in .args
        print inst           # __str__ allows args to printed directly
        x, y = inst          # __getitem__ allows args to be unpacked directly
        print 'x =', x
        print 'y =', y
    except KeyboardInterrupt:
        try:
            # CTRL-C pretty handling.
            print "Keyboard Interruption!. Skiping printout step. Press CTRL-C again to exit."
            time.sleep(1)
            return (2)
        except KeyboardInterrupt:
            sys.exit(1)


def analyze_domain(domain):
        """
        This function analyze the domain with every check we have
        """
        global debug
        global common_list_path
        global check_common_hosts_names
        global nmap_scantype
        global zone_transfer
        global net_block
        global output_file
        global nmap
        global output_directory
        global not_store_nmap
        global zenmap
        global subdomains_found
        global not_goog_mail
        global domain_data
        global webcrawl
        global output_file_handler
        global ignore_host_pattern
        global robtex_domains
        global all_robtex
        global domains_still_to_analyze
        global zenmap_command

        domain_data={}
        domain_data['IpsInfo']={}
        domain_data['DomainInfo']=[]


        try:
            if ignore_host_pattern :
                if ignore_host_pattern in domain:
                    return 0
            # First check if the hostname given is in fact a domain...
            try:
                print '\tChecking if the hostname {0} given is in fact a domain...'.format(domain)

                # If a host has a NS for its own, then we think its a domain
                if debug:
                    logging.debug('\t\t> Checking if {0} is a domain...'.format(domain),)
                host_name_ns = dns.resolver.query(domain, 'NS')
            except:
                logging.error('\tThe given name doesn\'t seem to be a domain since there are no NS servers assigned to it. Stopping.')
                logging.error('\tThe dnspython library in macos can not find domains such as com. It is a bug in the library. Linux can.\n')
                return -1 
            # Now we are sure its a domain!
            print
            logging.debug('Analyzing domain: {0}'.format(domain))
            # If an output directory was selected, we create an output file...
            if output_directory!=False:
                # Create different directories for the new domains
                output_directory=domain
                try:
                    os.mkdir(output_directory)
                except OSError:
                    try:
                        logging.warning('\tOutput directory already exists, press CTRL-C NOW if you want to override the files on it.')
                        time.sleep(2)
                        return (-1)
                    except KeyboardInterrupt:
                        pass
                output_file=output_directory+'/'+domain+'.txt'
                output_file_handler=open(output_file,'w')
                logging.info('\tOutput directory name: {0}'.format(output_directory))
            if output_file:
                logging.info('\tOutput summary file: {0}'.format(output_file))
            if ignore_host_pattern:
                logging.info('\tIgnoring host with this pattern: {0}\n'.format(ignore_host_pattern))
            if output_file!="":
                output_file_handler.writelines('Analysing domain : {0}\n'.format(domain))
                output_file_handler.writelines('\tOutput directory name: {0}\n'.format(domain))
                if output_file:
                    output_file_handler.writelines('\tOutput summary file: {0}\n'.format(output_file))
                if ignore_host_pattern:
                    output_file_handler.writelines('\tIgnoring host with this pattern: {0}\n\n\n'.format(ignore_host_pattern))
            # If we have DNS information for the domain...
            if dns_request(domain) != -1:
                # Check domain related emails using goog-mail.py
                if not_goog_mail==True:
                    check_domain_emails(domain)
                # If nmap is activated
                if nmap:
                    # Check for active hosts with nmap
                    check_active_host()
                    # Scan ports with nmap
                    host_info(domain)
                # If we can webcrawl
                if webcrawl == True and nmap:
                    web_crawl_domain()
                # Print out the final summary
                printout(domain,'',1)
                # If zenmap was selected, open zenmap with the topolog
                if zenmap == 1:
                    # Move the xml files to its own directory, so it is easier to see them with zenmap
                    if output_directory != False and not_store_nmap != 1:
                        try:
                            os.mkdir(output_directory + '/nmap/xml')
                            # Move everything to xml directory
                            os.system('mv ' + output_directory + '/nmap/*.xml ' + output_directory + '/nmap/xml')
                        except OSError:
                            print('There was an error creating the xml folder for storing the files for zenmap. Trying to continue.')
                    elif output_directory == False:
                        logging.debug('\tTo use zenmap you must specify an output directory and store nmap output files.')
                    # Do it more generic so other systems can use zenmap 
                    command_line = zenmap_command + ' ' + output_directory + '/nmap/xml'
                    args = shlex.split(command_line)
                    Popen(args)
                # Are you sure about this?
                if robin_hood == True:
                    logging.warning('Are you sure do you want to send an email with the report to every email address found in the domain??? ( No / Yes, I want )')
                    if output_file!="":
                        output_file_handler.writelines('Are you sure do you want to send an email with the report to every email address found in the domain??? ( No / Yes, I want )\n')
                    text2 = raw_input()
                    if text2 == 'Yes, I want':
                        robin_hood_send()
                    else:
                        print '... mmm I though so...'
                # If robtex domains were activated, search for them!
                if robtex_domains or all_robtex:
                    find_robtex_domains()
            # Close output file if we created it
            if output_directory!=False and output_file_handler:
                output_file_handler.close()
                output_file_handler=False
        except Exception as inst:
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            x, y = inst          # __getitem__ allows args to be unpacked directly
            print 'x =', x
            print 'y =', y


def find_robtex_domains():
    """
    This function takes each DNS server with ZT active in a domain and use the robtex site  to find other unrelated domains using that DNS server
    """
    global debug
    global domain_data
    global ns_servers_to_robtex
    global output_directory
    global output_file_handler
    global domains_still_to_analyze
    global all_robtex
    global robtex_domains
    try:

        import string
        import httplib
        import urllib2
        import re
        import random

        # This is not working: domain_analyzer_v0.5.py -d law.edu.ru -o law.edu.ru -b -a -n -g -v "in-addr.arpa" -D

        print 'Finding new unrelated domains to analyze with robtex.'
        if output_directory!=False:
            output_file_handler.writelines('Finding new unrelated domains to analyze with robtex.\n')

        # Search every DNS with ZT active in this domain
        for ip in domain_data['IpsInfo']:
            ip_vect=domain_data['IpsInfo'][ip]

            if robtex_domains or all_robtex:
                for dicts in ip_vect:
                    if dicts.has_key('HostName'):
                        hostname=dicts['HostName']
                    if dicts.has_key('ZT'):
                        # Now we store the dns server in the list (for recursion) but avoid repiting! 
                        # We use the IP because a lot of dns has several different names.
                        if not ns_servers_to_robtex.has_key(ip):
                            ns_servers_to_robtex[ip]=hostname        
                            if debug:
                                logging.debug('\tName server {0} ({1}) was added to be checked with robtex.'.format(ip, hostname))
            elif all_robtex:
                for dicts in ip_vect:
                    if dicts.has_key('HostName'):
                        hostname=dicts['HostName']
                    if dicts.has_key('NS'):
                        # Now we store the dns server in the list (for recursion) but avoid repiting! 
                        # We use the IP because a lot of dns has several different names.
                        if not ns_servers_to_robtex.has_key(ip):
                            ns_servers_to_robtex[ip]=hostname        
                            if debug:
                                logging.debug('\tName server {0} ({1}) was added to be checked with robtex.'.format(ip, hostname))


        # For each ns_server in queue to search...
        for ip in ns_servers_to_robtex:
            hostname=ns_servers_to_robtex[ip]

            # This is because the dictionary can grow recursively, so every time we check a dns server, we mark it as checked
            if hostname:
                logging.info('\tName server {0} ({1}) already had Zone Transfer, searching for more domains using it...'.format(ip, hostname))
                if output_directory!=False:
                    output_file_handler.writelines('\tName server {0} ({1}) had Zone Transfer, searching for more domains using it...\n')

                # For each DNS server ask robtex unrelated domains with the same DNS
                results_web = 'http://www.robtex.com/dns/'+ hostname +'.html'
                request_web = urllib2.Request(results_web)
                request_web.add_header('User-Agent','Mozilla/5.0 (X11; U; Linux x86_64; en-US) AppleWebKit/534.16 (KHTML, like Gecko) Chrome/10.0.648.205 Safari/534.16')
                opener_web = urllib2.build_opener()
                try:
                    text = opener_web.open(request_web).read()
                except:
                    print 'Sorry, www.robtex.com timed out' 


                # This is because the dictionary can grow recursively, so every time we check a dns server, we mark it as checked
                ns_servers_to_robtex[ip]=False

                # Here we should extract the unrelated domains 
                try:
                    #text2=text.split('<span id="sharedns">')[1].split('</div>')[0].split(')')[1]
                    text2=text.split('id="dns1"')[1].split('<div class="div4">')[0].split(')')[1]
                    temp_domains = re.findall('(href="\w[\w\.\-]+\.html")',text2)

                    logging.info('\tWe found {0} more domains:'.format(len(temp_domains)))
                    if output_directory!=False:
                        output_file_handler.writelines('\tWe found {0} more domains:\n'.format(len(temp_domains)))

                    # Extract the exact domain name from the href
                    for temp_domain in temp_domains:
                        unrelated_domain=temp_domain.split('href="')[1].split('.html"')[0].replace('\'','')

                        # Append it to main dictionary of domains to analyze
                        try:
                            # If the domain was there already, do not append it
                            t=domains_still_to_analyze.index(unrelated_domain)
                            if debug:
                                logging.debug('\t\t> Not adding domain {0} because it is repeated'.format(unrelated_domain))
                        except ValueError:
                            # If the domain wasn't there, append it
                            if debug:
                                logging.debug('\t\t> Adding domain {0}'.format(unrelated_domain))
                            print '\t\t{0}'.format(unrelated_domain)
                            if output_file!="":
                                output_file_handler.writelines('\t\t{0}'.format(unrelated_domain))
                            domains_still_to_analyze.append(unrelated_domain)
                            pass
                        except Exception as inst:
                            print type(inst)     # the exception instance
                            print inst.args      # arguments stored in .args
                            print inst           # __str__ allows args to printed directly

                except:
                    logging.info('\t\tNo more domains found in robtex')
                    if output_directory!=False:
                        output_file_handler.writelines('\t\tNo more domains found in robtex\n')



    except Exception as inst:
        print type(inst)     # the exception instance
        print inst.args      # arguments stored in .args
        print inst           # __str__ allows args to printed directly
        x, y = inst          # __getitem__ allows args to be unpacked directly
        print 'x =', x
        print 'y =', y
    except KeyboardInterrupt:
        try:
            # CTRL-C pretty handling.
            print "Keyboard Interruption!. Skiping robtex step. Press CTRL-C again to exit."
            time.sleep(1)
            return (2)

        except KeyboardInterrupt:
            sys.exit(1)




def robin_hood_send():
        """
        This function sends an email with the report of domain analysis to every email address found in the domain
        """
        global debug
        global output_file
        global output_directory
        global domain_data
        global webcrawl
        global max_amount_to_crawl

        try:

            # For every MX host in every domain
            for ip in domain_data['IpsInfo']:
                # We extract IP information
                ip_registry=domain_data['IpsInfo'][ip]

                if debug:
                    print '\t> For IP : {0}'.format(ip)
                # We extract its vector
                ip_vect=domain_data['IpsInfo'][ip]


                # First we search for every MX type!
                temp_host_name_to_crawl=[]
                for dicts in ip_vect:
                    if dicts.has_key('Type'):
                        # Store last domain for this IP
                        if 'MX' in dicts['Type']:
                            mail_server=dicts.get('Type')


                            #import smtplib

                            ## Import the email modules we'll need
                            #from email.mime.text import MIMEText

                            #me = 'robin_hood@gmail.com'
                            #you = 'eldraco@gmail.com'
                            ## Open a plain text file for reading.  For this example, assume that
                            ## the text file contains only ASCII characters.
                            #fp = open(textfile, 'rb')
                            ## Create a text/plain message
                            #msg = MIMEText(fp.read())
                            #fp.close()

                            ## me == the sender's email address
                            ## you == the recipient's email address
                            #msg['Subject'] = 'Report of the free analysis of your domain'
                            #msg['From'] = me
                            #msg['To'] = you

                            ## Send the message via our own SMTP server, but don't include the
                            ## envelope header.
                            #s = smtplib.SMTP()
                            ##s.sendmail(me, you, msg.as_string())
                            #s.quit()



        except Exception as inst:
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly




def web_crawl_domain():
        """
        This function use our exterernal crawler program to crawl for web vulns
        """
        global debug
        global output_file
        global output_directory
        global domain_data
        global webcrawl
        global max_amount_to_crawl
        global output_file_handler
        global download_files

        try:
            # Crawler is our own web crawler that tries to find web non-aggresive vulns
            import crawler

            # We should try to crawl every website (in its correct port) on every host. And perhaps we have to try to crawl it using its
            # IP address if the host name does not work

            print '\tWebCrawling domain\'s web servers... up to {0} max links.'.format(max_amount_to_crawl)
            if output_file!="":
                output_file_handler.writelines('\tWebCrawling domain\'s web servers... up to {0} max links.\n'.format(max_amount_to_crawl))

            # If we are debbuging, so the crawler
            if debug:
                crawler.debug=True
            if output_directory != "":
                crawler.write_to_file=True

            if download_files:
                crawler.fetch_files_opt = True

            # For each IP in the main dictionary
            for ip in domain_data['IpsInfo']:
                # We extract IP information
                ip_registry=domain_data['IpsInfo'][ip]

                if debug:
                    print '\t> For IP : {0}'.format(ip)
                # We extract its vector
                ip_vect=domain_data['IpsInfo'][ip]


                # First we search for every hostname!
                temp_host_name_to_crawl=[]
                for dicts in ip_vect:
                    if dicts.has_key('HostName'):
                        # Store last domain for this IP
                        temp_host_name_to_crawl.append(dicts.get('HostName'))
                        if debug:
                            logging.debug('\t\t> Adding hostname to crawl: {0}'.format(dicts.get('HostName')))

                #Uniquify this list (sometimes a hostname appers twice. once as A record and once as MX or NS record)
                host_name_to_crawl_dict=set(temp_host_name_to_crawl)


                temp_port_info=""
                port_number=""
                crawler_results=[]
                # Now look for web ports in these hostnames
                for moredicts in ip_vect:
                    if moredicts.has_key('PortInfo'):
                        temp_port_info= moredicts.get('PortInfo')
                        # Find only web ports
                        if temp_port_info.find('http') != -1 and temp_port_info.find('?')==-1:
                            # Separate the port number
                            port_number=temp_port_info.split('/')[0]
                            if debug:
                                logging.debug('\t\t> We have got a new web port: {0}'.format(port_number))
                            if temp_port_info.find(' ssl/http ') != -1:
                                # It was an https port!
                                for hntc in host_name_to_crawl_dict:
                                    if port_number == '443':
                                        temp_host_name='https://'+hntc
                                    else:
                                        temp_host_name='https://'+hntc+':'+port_number
                                    if debug:
                                        logging.debug('\tCrawling ssl site {0}, port {1}, max {2} links'.format(temp_host_name,port_number,max_amount_to_crawl))
                                    #
                                    # Here we crawl!!!
                                    #
                                    print
                                    crawler.crawl_result=[]
                                    crawler.crawl_site(temp_host_name,max_amount_to_crawl)



                            else:
                                for hntc in host_name_to_crawl_dict:
                                    if port_number == '80':
                                        temp_host_name='http://'+hntc
                                    else:
                                        temp_host_name='http://'+hntc+':'+port_number
                                    if debug:
                                        logging.debug('\tCrawling site {0}, port {1}, max {2} links'.format(temp_host_name,port_number,max_amount_to_crawl))
                                    #
                                    # Here we crawl!!!
                                    #
                                    print
                                    crawler.crawl_result=[]
                                    crawler.crawl_site(temp_host_name,max_amount_to_crawl)

                            # We store the information from the crawler in the main dictionary
                            for result in crawler.crawl_results:
                                ip_registry.append(result)
                                a=[]
                                a=copy.deepcopy(ip_registry)
                                domain_data['IpsInfo'][ip]=a


        except Exception as inst:
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly



def world_domination_check():
                                    # Here we crawl!!!
    """
    This function analyzes every .gov, .mil, .org and .net of every country on the world
    """

    try:
        global debug
        global output_directory
        global output_file

        gtld_domains=['biz', 'info','net','com','org','edu','gov','me', 'tv','name']
        tld_domains=['edu','gov','mil','net','org','ag','co','go']
        cc_domains=['.AC', '.AD', '.AE', '.AERO', '.AF', '.AG', '.AI', '.AL', '.AM', '.AN', '.AO', '.AQ', '.AR', '.ARPA', '.AS', '.ASIA', '.AT', '.AU', '.au', '.AW', '.AX', '.AZ', '.BA', '.BB', '.BD', '.BE', '.BF', '.BG', '.BH', '.BI', '.BIZ', '.BJ', '.BL', '.BM', '.BN', '.BO', '.BQ', '.BR', '.BS', '.BT', '.BV', '.BW', '.BY', '.BZ', '.CA', '.CAT', '.CC', '.CD', '.CF', '.CG', '.CH', '.CI', '.CK', '.CL', '.CM', '.CN', '.CO', '.CO', '.COM', '.COOP', '.CR', '.CU', '.CV', '.CW', '.CX', '.CY', '.CZ', '.DE', '.DJ', '.DK', '.DM', '.DO', '.DZ', '.EC', '.EDU', '.EE', '.EG', '.EH', '.ER', '.ES', '.ET', '.EU', '.FE', '.FI', '.FJ', '.FK', '.FM', '.FO', '.FR', '.GA', '.GB', '.GD', '.GE', '.GF', '.GG', '.GH', '.GI', '.GL', '.GM', '.GN', '.GP', '.GQ', '.GR', '.GS', '.GT', '.GU', '.GW', '.GY', '.HK', '.HM', '.HN', '.HR', '.HT', '.HU', '.ID', '.IE', '.IL', '.IM', '.IN', '.INFO', '.INT', '.IO', '.IQ', '.IR', '.IS', '.IT', '.JE', '.JM', '.JO', '.JOBS', '.JP', '.KE', '.KG', '.KH', '.KI', '.KM', '.KN', '.KP', '.KR', '.KW', '.KY', '.KZ', '.LA', '.LB', '.LC', '.LI', '.LK', '.LR', '.LS', '.LT', '.LU', '.LV', '.LY', '.MA', '.MC', '.MD', '.ME', '.MF', '.MG', '.MH', '.MIL', '.MK', '.ML', '.MM', '.MN', '.MO', '.MOBI', '.MP', '.MQ', '.MR', '.MS', '.MT', '.MU', '.MUSEUM', '.MV', '.MW', '.MX', '.MY', '.MZ', '.NA', '.NAME', '.NC', '.NE', '.NET', '.NF', '.NG', '.NI', '.NL', '.NO', '.NP', '.NR', '.NU', '.NZ', '.OM', '.ORG', '.PA', '.PE', '.PF', '.PG', '.PH', '.PK', '.PL', '.PM', '.PN', '.PR', '.PRO', '.PS', '.PT', '.PW', '.PY', '.QA', '.RE', '.RO', '.RS', '.RU', '.RW', '.SA', '.SB', '.SC', '.SD', '.SE', '.SG', '.SH', '.SI', '.SJ', '.SK', '.SL', '.SM', '.SN', '.SO', '.SR', '.ST', '.SU', '.SV', '.SX', '.SY', '.SZ', '.TC', '.TD', '.TEL', '.TF', '.TG', '.TH', '.TJ', '.TK', '.TL', '.TM', '.TN', '.TO', '.TP', '.TR', '.TRAVEL', '.TT', '.TV', '.TW', '.TZ', '.UA', '.UG', '.UK', '.UM', '.US', '.UY', '.UZ', '.VA', '.VC', '.VE', '.VG', '.VI', '.VN', '.VU', '.WF', '.WS', '.YE', '.YT', '.ZA', '.ZM', '.ZW']

        for tld in tld_domains:
            for cc in cc_domains:
                output_directory=tld+cc
                output_file=tld+cc+'.txt'
                domain=tld+cc
                analyze_domain(domain)
        for gtld in gtld_domains:
            output_directory=gtld
            output_file=gtld+'.txt'
            domain=gtld
            analyze_domain(domain)



    except Exception as inst:
        print type(inst)     # the exception instance
        print inst.args      # arguments stored in .args
        print inst           # __str__ allows args to printed directly




def main():
    try:
        global debug
        global check_common_hosts_names
        global use_common_list
        global common_list_path
        global nmap_scantype
        global zone_transfer
        global net_block
        global output_file
        global nmap
        global output_directory
        global not_store_nmap
        global zenmap
        global subdomains_found
        global not_goog_mail
        global not_subdomains
        global create_pdf
        global robin_hood
        global webcrawl
        global max_amount_to_crawl
        global world_domination
        global countrys
        global geoip_cache
        global colors
        global check_spf
        global amount_of_random_domains
        global ignore_host_pattern
        global robtex_domains
        global domains_still_to_analyze
        global download_files
        global all_robtex
        global zenmap_command

        domain=""

        e=""

        opts, args = getopt.getopt(sys.argv[1:], "abBcCd:DefFghijk:lL:m:nopqrstVv:wx:z", ["help","version","debug","domain=","not-common-hosts-names","not-zone-transfer","not-net-block","store-output","i","not-scan-or-active","resolve-zone","not-store-nmap","zenmap","goog-mail","not-subdomains","create-pdf","robin-hood","not-webcrawl","max-amount-to-crawl=","world-domination","not-countrys","not-colors","not-spf","random-domains=","ignore-host-pattern=","nmap-scantype=","robtex-domains","download-files","all-robtex","common-hosts-list="])

    except getopt.GetoptError: usage()


    for opt, arg in opts:
        if opt in ("-h", "--help"): version(); usage()
        if opt in ("-V", "--version"): version();exit(1)
        if opt in ("-D", "--debug"): debug=1
        if opt in ("-i", "--i"): e=True
        if opt in ("-d", "--domain"): domain=arg
        if opt in ("-L", "--common-hosts-list"): common_list_path = arg; use_common_list = True
        if opt in ("-j", "--not-common-hosts-names"): check_common_hosts_names=False
        if opt in ("-t", "--zone-transfer"): zone_transfer=False
        if opt in ("-n", "--not-net-block"): net_block=False
        if opt in ("-o", "--store-output"): output_directory=True
        if opt in ("-a", "--not-scan-or-active"): nmap=0
        if opt in ("-p", "--not-store-nmap"): not_store_nmap=1
        if opt in ("-e", "--zenmap"): zenmap=1
        if opt in ("-g", "--goog-mail"): not_goog_mail=False
        if opt in ("-s", "--not-subdomains"): not_subdomains=True
        if opt in ("-f", "--create-pdf"): create_pdf=True
        if opt in ("-r", "--robin-hood"): robin_hood=True
        if opt in ("-l", "--world-domination"): world_domination=True
        if opt in ("-w", "--not-webcrawl"): webcrawl=False
        if opt in ("-m", "--max-amount-to-crawl"): max_amount_to_crawl=int(arg)
        if opt in ("-F", "--download-files"): download_files=True
        if opt in ("-c", "--countrys"): coutrys=False
        if opt in ("-C", "--not-colors"): colors=False
        if opt in ("-q", "--not-spf"): check_spf=False
        if opt in ("-k", "--random-domains"): amount_of_random_domains=int(arg)
        if opt in ("-v", "--ignore-host-pattern"): ignore_host_pattern=arg
        if opt in ("-x", "--nmap-scantype"): nmap_scantype=arg
        if opt in ("-b", "--robtex-domains"): robtex_domains=True
        if opt in ("-B", "--all-robtex"): all_robtex=True


    try:
        # Configure colors
        if colors:
            root = logging.getLogger()
            root.setLevel(logging.DEBUG)
            root.addHandler(ColorizingStreamHandler())
        # print version
        version()
        # Change socket timeout
        # This avoids some ZT tries to last for ever!
        socket.setdefaulttimeout(10)
        # Change nmap options
        if '-p' in nmap_scantype:
            nmap_scantype.replace('-F','')
        # Make sure zenmap binary is there
        if zenmap:
            if call("type zenmap", shell=True, stdout=PIPE, stderr=PIPE) == 0:
                # Most linux
                # zenmap exists
                zenmap_command = 'zenmap'
            elif call("type /Applications/Zenmap.app/Contents/MacOS/zenmap.bin", shell=True, stdout=PIPE, stderr=PIPE) == 0:
                # For macos installed with the dmg for zenmap
                # zenmap exists
                zenmap_command = '/Applications/Zenmap.app/Contents/Resources/bin/zenmap'
            else:
                # No zenmap
                zenmap = False
                print('Zenmap disabled because it was not found in the system.')
        # Add a . to the domain name. This is to avoid somo local DNS searches, specially in macos. Where the domain can appear as non existant. 
        # This allow us to search for TLDs such as 'com' domain. The final query is then 'com.' 
        # In the case of normal domains, such as, 'test.com', the query ends up being 'test.com.'
        domain += '.'
        # Control that the domain name does not start with a '.'
        if domain[0] == '.':
            domain = domain[1:]
            print("Domains should not start with a '.'. So I\'m stripping it off. The domain I\'m looking for now is: {}".format(domain))

        #
        # Normal way, NOT World Domination!
        #
        if len(domain)!=0 and world_domination == False:
            # Check if zenmap and 'not nmap' options are not enabled at the same time
            if zenmap == 1 and nmap == 0:
                logging.warning('\tWarning. You request to use Zenmap but disable the use of nmap. Do not use -a option if you want -e option.')
                exit (-1)

            # Check for parameter inconsistences
            if output_directory == False and create_pdf == True:
                logging.warning('\tWarning. You request to use create a pdf but no output directory was indicated.')
                exit (-1)

            if output_directory == False and download_files == True:
                logging.warning('\tWarning. You request to use download files but no output directory was indicated.')
                exit (-1)

            # Do we have GeoIP?? CHECK IT WITHOUT COUNTRYS
            if countrys:
                try:
                    import GeoIP
                    geoip_cache = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)
                except:
                    countrys=False
                    logging.warning('\tWARNING!! You don\'t have GeoIP libraries. apt-get install python-geoip\n\n')
            # If selected, find N random domains and analyze them
            if amount_of_random_domains:
                domain_list = find_and_analyze_random_domains(domain, amount_of_random_domains)
            else:
                # Common analysis of one domain
                domains_still_to_analyze.append(domain)
                # For every domain found, we analyze them
                for unrelated_domain in domains_still_to_analyze:
                    print
                    logging.info('Domains still to check: {0}'.format(len(domains_still_to_analyze)))
                    # Analyze the main domain
                    analyze_domain(unrelated_domain)
                    # We delete it from the list
                    domains_still_to_analyze.remove(unrelated_domain)
            # Now we will analyze each subdomain found
            if not_subdomains == False:
                for subdomain in subdomains_found:
                    print
                    analyze_domain(subdomain)
        # WORLD DOMINATION!!!!
        # We don't recomend to use world-domination and robin-hood at the same time...
        elif world_domination == True and robin_hood == False and nmap==0:
            logging.warning('WARNING! World domination mode activate!, are you sure? ( No / Yes, I\'m sure. )')
            text = raw_input()

            if text == 'Yes, I\'m sure.':

                # Check if zenmap and 'not nmap' options are not enabled at the same time
                if zenmap == 1 and nmap == 0:
                    logging.warning('\tWarning. You request to use Zenmap but disable the use of nmap. Do not use -a option if you want -e option.')
                    exit (-1)
                # If not, add traceroute to nmap
                #elif zenmap == 1 and nmap != 0:
                    #nmap_scantype_temp=nmap_scantype
                    #nmap_scantype=nmap_scantype+' --traceroute'

                # Check for parameter insonsistences
                if output_directory == False and create_pdf == True:
                    logging.warning('\tWarning. You request to use create a pdf but do not indicate an output directory.')
                    exit (-1)

                # Do we have GeoIP??
                if countrys:
                    try:
                        import GeoIP
                        geoip_cache = GeoIP.new(GeoIP.GEOIP_MEMORY_CACHE)

                    except:
                        countrys=False
                        logging.warning('\tWARNING! You don\'t have GeoIP libraries. apt-get install python-geoip')

                # HERE
                world_domination_check()

                # Now we will analyze each subdomain found in the world
                if not_subdomains==False:
                    for subdomain in subdomains_found:
                        analyze_domain(subdomain)
            else:
                print 'I though so...'



        elif e:
            tt()
        else:
            version()
            usage()


    except KeyboardInterrupt:
        # CTRL-C pretty handling.
        if output_directory!=False and output_file_handler:
            output_file_handler.close()
        print "Keyboard Interruption!. Closing files and exiting."
        sys.exit(1)


if __name__ == '__main__':
    main()
