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
#
# Author:
# Sebastian Garcia eldraco@gmail.com
# Veronica Valeros vero.valeros@gmail.com
#
# Changelog
# 0.4
#    - Follow parcial redirect. If URL redirects and no more links found in page, then follow redirect linked to the domain by default.
#    - Now it replaces existent spaces in URL strings with %20 to properly crawl that URLs.
#    - Follow redirection of any kind added
#    - Now it extract links from iframes and img tags.
#    - Add possibility to stop crawling one URLs or the rest of them and analyze the info obtained until that point
#    - Increased speed of crawling after revision of the source code
#       - Order the output of open folders by URL and directory
#    - Fixed bugs in well form the links extracted from URL response
#    - Identify relative links
#    - Detection of references in URL like: 'file:', 'feed=','mailto:' improved
#    - Crawl https and web sites in not common ports
# 0.3
#    - Identify more file extensions (zip,swf,sql,rar,etc.)
#     - Inform when site doesn't exists
#     - Implemented a crawl limit with '-d' option. If '-d xx' option is set then we crawl up to xx URLs
#    - Now accept URL with and without http, Ex.: http://www.site.com and www.site.com
#    - Identify only emails related to domain
#    - Fixed bug related with '/' and empty paths 
# 0.2 
#    - Identify simple directory indexing
#    - Identify directories
#    - Identify a small group of file extensions
# 0.1
#    - Crawling of web pages via href analysis
#    - Creation
#
# TODO
# - Follow redirect
# - Allow to choose or select file types to download
# - Inform or search about allowed methods in open folder.
# - Colorize

"""
Crawler function allows to crawl a entire site. It obtain the source of the main page for the URL provided and
search for links in it. Actually only detect HREF links. See -h option to get a full list of options.
"""

# standar imports
import sys
import re
import getopt
import urllib2
import urlparse
import copy
import os
import time
import socket
import datetime

####################
# Global Variables
debug=False
vernum='0.4'
verbose=False
write_to_file=False
fetch_files_opt=False
sub_domains=False
follow_redirect=True

# This is for identify links in a HTTP answer
#linkregex = re.compile('[^>](?:href=|src=|content=\"http)[\'*|\"*](.*?)[\'|\"]',re.IGNORECASE)
linkregex = re.compile('(?:href\=|src\=|content\=\"http)[\'*|\"*](.*?)[\'|\"].*?>',re.IGNORECASE)
linkredirect = re.compile('(?:open\\(\"|url=|URL=|location=\'|src=\"|href=\")(.*?)[\'|\"]')

# In this variable we store only the main domain to crawl.
main_domain=""
accept_domain=""
host_name=""
url_scheme=""
link_full_path=""

## VECTORES QUE ALMACENAN LINKS 
#NOTA: Hay que revisarlos, estan puestos al ponchazo

# Vector that stores the URLs to crawl. At first the URL passed by user and lately it is fill with URLs found in the pages crawled.
#URL = set([])
URL = []

# Vector that stores URLs already crawled
#crawled = set([])
crawled = []

# Save directories
directories = []

# Save directories with indexing 
directories_with_indexing = []

# Save external links
externals= []

# Save files
link_to_files = []

# All files
allfiles = []

# Mails found
emails = []

crawl_results=[]

output_data={}
#output_data['LinksCrawled']=[]
#output_data['LinksToFiles']=[]
#output_data['LinksExternals']=[]
#output_data['Emails']=[]
#output_data['Directories']=[]
#output_data['DirectoriesWithIndexing']=[]
# To detect a file extension on url's path and not ask for response.
extensions=[]
#'.XML','.xml','.MSI','.msi','.vbs','.db','.asc','.ASC','.js','.sql','.SQL','.rar','.RAR','.mdb','.jar','.JAR','.mp3','.MP3','.mpg','.sty','.jpg','.JPG','.jpeg','.JPEG','.png','.gif','.GIF','.dat','.DAT','.f','.c','.h','.cnf','.flv','.FLV','.wma','.swf','.pdf','.PDF','.exe','.EXE','.odt','.txt','.TXT','.xls','.XLS','.docx','.DOCX','.py','.zip','.ZIP','.tar','.tar.gz','.tar.bz','.tar.bz2','.7z','.doc','.DOC','.ppt','.PPT','.pps','.css','.CSS','.ico','.ICO','.bmp','.BMP','.avi','.AVI','.mkv','.MKV']


splitters = ['Javascript:','javascript:','feed:','feed=','#','mms:','file:','cid:','maito:','src=','skype:']

# HTTP Response Codes
# -------------------
error_codes={}
error_codes['200']='200 OK'
error_codes['300']='300 Multiple Choices'
error_codes['301']='301 Moved Permanently'
error_codes['302']='Moved'
error_codes['305']='305 Use Proxy'
error_codes['307']='307 Temporary Redirect'
error_codes['400']='400 Bad Request'
error_codes['401']='401 Unauthorized'
error_codes['403']='403 Forbidden'
error_codes['404']='404 Not Found'
error_codes['405']='405 Method Not Allowed'
error_codes['407']='407 Proxy Authentication Required'
error_codes['408']='408 Request Timeout'
error_codes['500']='500 Internal Server Error'
error_codes['503']='503 Service Unavailable'
error_codes['504']='504 Gateway Timeout'
error_codes['505']='505 HTTP Version Not Supported'


# End of global variables
###########################


# Print version information and exit
def version():
    """
    This function prints the version of this program. It doesn't allow any argument.
    """
    print "+----------------------------------------------------------------------+"
    print "| "+ sys.argv[0] + " Version "+ vernum +"                                      |"
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
    """
    This function prints the posible options of this program.
    """
    print "+----------------------------------------------------------------------+"
    print "| "+ sys.argv[0] + " Version "+ vernum +"                                      |"
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
    print "\nUsage: %s <options>" % sys.argv[0]
    print "Options:"
    print "  -u, --url                            URL to start crawling."
    print "  -m, --max-amount-to-crawl           Max deep to crawl. Using breadth first algorithm"
    print "  -w, --write-to-file                  Save summary of crawling to a text file. Output directory is created automatically."
    print "  -s, --subdomains                     Also scan subdomains matching with url domain."
    print "  -r, --follow-redirect                Do not follow redirect. By default follow redirection at main URL." 
    print "  -f, --fetch-files                    Download there every file detected in 'Files' directory. Overwrite existing content."
    print "  -F, --file-extension                 Download files specified by comma separated extensions. This option also activates 'fetch-files' option. 'Ex.: -F pdf,xls,doc' " 
    print "  -d, --docs-files                     Download docs files:xls,pdf,doc,docx,txt,odt,gnumeric,csv, etc. This option also activates 'fetch-files' option." 
    print "  -E, --exclude-extensions             Do not download files that matches with this extensions. Options '-f','-F' or '-d' needed." 
    print "  -h, --help                           Show this help message and exit."
    print "  -V, --version                        Output version information and exit."
    print "  -v, --verbose                        Be verbose"
    print "  -D, --debug                          Debug."
    print
    sys.exit(1)

#################
# CRAWL EVERY URL 
#################
def crawl_site(base_url_to_crawl,max_amount_to_crawl):
    """
    This function crawls the entire site up to max_amount_to_crawl urls

    Parameters:
    site_url    The url to crawl. Ex.: http://www.sitetocrawl.com
    max_amount_to_crawl    The maximum numer of urls to crawl. Integer.
    """
    
    global URL
    global crawled
    global directories
    global directories_with_indexing
    global externals
    global link_to_files
    global allfiles
    global emails
    global crawl_result  
    global main_domain
    global host_name
    global url_scheme
    global link_full_path
    global fetch_files_opt
    global sub_domains
    global debug
    global accept_domain
    global follow_redirect
    global output_data
    
    # We clean the variables
    URL = []
    directories = []
    directories_with_indexing = []
    externals= []
    link_to_files = []
    allfiles = []
    emails = []
    crawl_results=[]
    main_domain=""
    host_name=""
    accept_domain=""
    url_scheme=""
    link_full_path=""
    url_parsed=""
    url_tmp=""
    
    site_url = base_url_to_crawl
    crawled=[]

    output_data={}
    output_data['LinksCrawled']=[]
    output_data['LinksToFiles']=[]
    output_data['LinksExternals']=[]
    output_data['Emails']=[]
    output_data['Directories']=[]
    output_data['DirectoriesWithIndexing']=[]
    
    
    #Program
    try:
        print '\t+ URL to crawl: {0}'.format(site_url)
        print '\t+ Date: {0}\n'.format(str(datetime.date.today()))
        if site_url.__len__() != 0:
            # We extract and store the domain to crawl to limit the crawl to this domain exclusively
            # If site_url is 'http://www.site.com' then main_domain= 'site.com' and host_name='www.site.com'
            url_parsed=urlparse.urlparse(site_url)
            if url_parsed.scheme == "" or len(url_parsed.scheme)>5:
                url_scheme="http"
                site_url=url_scheme+'://'+site_url
            else:
                url_scheme=url_parsed.scheme
            
            url_parsed=urlparse.urlparse(site_url)
            host_name=url_parsed.netloc
            main_domain=host_name
            
            
            if sub_domains:
                try:
                    if len(host_name.split('.'))>2:
                        accept_domain=host_name.split('www.')[1]
                    else:
                        accept_domain=host_name
                except:
                    accept_domain=host_name
            else:
                accept_domain=host_name
            
            # We crawl the first URL given by user
            print '\t+ Crawling URL: {0}:'.format(site_url)
            print '\t\t+ Links:',
        
            url_tmp = site_url
            # max_amount_to_crawl defines how many URLs are going to be crawled. By default 5000 is the max.
            # this variable is decremented on each loop
            while max_amount_to_crawl:
                # We inform in debug mode how many URLs we have crawled and the max amount of URL to crawl 
                if debug:
                    print '\n\t\t\t> Crawling URL {0} up to max {1} urls'.format(url_tmp,max_amount_to_crawl),
            
                # We crawl the url
                # crawl_url() function populates the variable URL
                exit_status = crawl_url(url_tmp)
                if exit_status == -1:
                    #max_amount_to_crawl=max_amount_to_crawl-1
                    pass
                elif exit_status == -2:
                    try:
                        print '\n\t\t\t\t> Keyboard interruption! Waiting 1 seconds to continue crawling the next URL'
                        print '\t\t\t\t> Hit CTRL-C again to skip the rest of the URLs to crawl!'
                        time.sleep(1.5)
                        pass
                    except KeyboardInterrupt:
                        break    
                elif exit_status == -3:
                    if debug or max_amount_to_crawl < 2:
                        print '\n\t\t\t\t> No more URLs to crawl.' 
                elif exit_status == -4:
                    print '(File! Not crawling it.)',
                    max_amount_to_crawl=max_amount_to_crawl+1
                else:
                    if debug:
                        print '\n\t\t\t> URL crawled successfully',
                
                # We extract next url to crawl
                try:
                    url_tmp=URL[0]
                    URL.remove(url_tmp)
                    if debug:
                        print '\n\t\t\t> Removed url {0}. {1} URLs found so far'.format(url_tmp,len(URL)),
                except:
                    if debug:
                        print '\n\t\t\t> The URL vector is empty. No more URLs to crawl'
                    max_amount_to_crawl=0
                    continue

                # We decrement Max_amount_to_crawl. If it is lower or equal to zero the stopping in next iteration
                if max_amount_to_crawl != 0:
                    max_amount_to_crawl=max_amount_to_crawl-1

                if debug:
                    print '\n\t\t\t> We decrement the integer max_amount_to_crawl to {0}'.format(max_amount_to_crawl),

            if crawled.__len__() <= 1:
                result = directory_indexing()
                if (fetch_files_opt):
                    if debug:
                        print '\n\t\t> Descargando files...',
                    result = fetch_files()
                output_data['LinksCrawled']=crawled
                output_data['LinksToFiles']=link_to_files
                output_data['LinksExternals']=externals
                output_data['Emails']=emails
                output_data['Directories']=directories
                output_data['DirectoriesWithIndexing']=directories_with_indexing
                print '\n'
                return -1
            else:
                # We identify directories on crawled URLs and check for indexing in them
                result = directory_indexing()
                if (fetch_files_opt):
                    if debug:
                        print '\n\t\t> Descargando files...',
                    result = fetch_files()
                # Here we sort the vectors to print in a nice way.
                crawled.sort()
                directories.sort()
                externals.sort()
                emails.sort()
                directories_with_indexing.sort()
                link_to_files.sort()
                

                if write_to_file:
                    if debug:
                        print '\n\t\t> Guardando en disco la informacion...'
                    host_name=base_url_to_crawl
                    result = print_to_file()
                
                print '\n\t+ Crawl finished successfully.'
                if debug:
                    print '\t\t> Calling Printout() function...'
                printout()

                base_url_to_crawl=""
                
                if debug:
                    print '\t\t> Clean exit. Return 1'

                output_data['LinksCrawled']=crawled
                output_data['LinksToFiles']=link_to_files
                output_data['LinksExternals']=externals
                output_data['Emails']=emails
                output_data['Directories']=directories
                output_data['DirectoriesWithIndexing']=directories_with_indexing
                
                return 1

        else:
            #printout()
            print '\t> Check if the URL is like "http://xxx.xxxxx.xx". Exiting.'
            return -3
        
    except:
        print '\t\t> Error in crawl site'
        return -4
        
    
###########
# CRAWL URL 
###########
def crawl_url(url_base):
    """
    This function crawl the entire domain recursively. Crawl in deep.
    """
    global debug
    global URL
    global linkregex
    global main_domain
    global accept_domain
    global host_name
    global crawled
    global externals
    global link_to_files
    global allfiles
    global extensions
    global emails
    global verbose
    global url_scheme
    global link_full_path
    global sub_domains
    global error_codes
    
    #Variables
    response=""
    link=""
    url_to_crawl=""
    url=""
    email=""
    link_full_path=""
    crawled_url = ""
    request_web=""
    opener_web=""
    response=""

    # Maybe this better have to be in main section. But if this function is used externaly it can cause a problem.
    extensions_recognized="rss,xsl,xml,msi,vbs,db,asc,js,sql,rar,mdb,jar,mpg,sty,dat,f,c,h,cnf,flv,wma,swf,py,bz2,7z,css,ico,avi,mkv,doc,ppt,pps,xls,docx,pptx,ppsx,xlsx,sxw,sxc,sxi,odt,ods,odg,odp,pdf,wpd,txt,gnumeric,csv,asc,sql,rar,mdb,jar,mp3,sty,jpg,jpeg,png,gif,exe,py,zip,tar,gz,bz,bmp"
    for i in extensions_recognized.split(','):
        extensions.append('.'+i.lower())
        extensions.append('.'+i.upper())
    ######
    #Program
    ######
    #URL.append(url_base)

    try:
        # Here we extract the complete URL to crawl. Commonly it has the form: http://www.xxxxx.com
        #url_to_crawl = URL[0]
        url_to_crawl = url_base 
        try:
            URL.remove(url_to_crawl)
        except:
            pass

        print '\n\t\t\t+ Crawling {0}'.format(url_to_crawl),
        
        # We parse the URL to identify domains and paths of the URL
        url = urlparse.urlparse(url_to_crawl)
        
        # Here we get the data of the URL
        try:
            # Here we set a timeout to limit response time.
            #socket.setdefaulttimeout(5)
            if debug:
                print '\n\t\t\t\t> Asking for response...',
            request_web = urllib2.Request(url_to_crawl.replace(" ","%20"))
            request_web.add_header('User-Agent','Mozilla/4.0 (compatible;MSIE 5.5; Windows NT 5.0)')
            opener_web = urllib2.build_opener()
            response = opener_web.open(request_web)

            if not response.headers.typeheader.startswith('text/html'):
                if url_to_crawl not in link_to_files:
                    link_to_files.append(url_to_crawl)
                return -4

            # We add the url to the list of crawled URLs if this exist
            crawled.append(url_to_crawl)
        except urllib2.HTTPError,error_code:
            if debug:
                print '\n'
            if error_code.getcode() == 302:
                link = linkregex.findall(error_code.read()).pop(0)
                print '(REDIRECTING TO: {0})'.format(link),
                #print 'Link redirection: {0}'.format(link.pop(0))
                crawled.append(url_to_crawl + ' (REDIRECTS TO: ' + link + ')')
            else:
                print ' ({0})'.format(error_codes[str(error_code.getcode())]),
                crawled.append(url_to_crawl + ' (' + error_codes[str(error_code.getcode())] + ')')
            return -1    
        except urllib2.URLError,error_code:
            if debug:
                print '\n\t\t\t\t> ({0})'.format(error_code.reason)
            else:
                print ' ({0})'.format(error_code.reason),
            crawled_url='{0} ({1})'.format(url_to_crawl,error_code.reason)
            if crawled_url not in crawled:
                crawled.append(crawled_url)
            return -1    
        
        # We got a response! Reading it and store it in msg
        if debug:
            print '\n\t\t\t\t> Reading response obtained...'
        msg = response.read()
        
        # If you really want to see the response of each link crawled uncomment the following two lines
        #if debug and verbose:
        #    print '\t\t\t\t> Message obatained in response: \n++++++++++++++++++++++\n{0}\n++++++++++++++++++++++\n'.format(msg)
        
        # We look for links in the response message
        links = linkregex.findall(msg)
        if not(links):
            if debug:
                print '\t\t\t\t> No links found in this URL.'
            links = linkredirect.findall(msg)
            if not (links):
                return -1
            else:
                print '(REDIRECTING TO: {0})'.format(links[0]),
                crawled[crawled.index(url_to_crawl)] = url_to_crawl + ' (REDIRECTS TO: ' + links[0] + ')'
                return 1
        
        # We examine each link found and we add it to crawl if it correspond to the domain that is being crawled
        for link in (links.pop(0) for _ in xrange(len(links))):
            if len(link) > 2:
                link_full_path=""
                if debug:
                    print '\t\t\t\t> Link extracted: {0}'.format(link)
                try:
                    try:
                        #if url.path != "" and not url.path.endswith('/'):
                        if url.path != "":
                            if '.' not in url.path:
                                link_full_path = url_to_crawl 
                            else:
                                link_domain=url_to_crawl.split('/')[1:-1]
                                link_full_path = url.scheme + '://' + link_domain[1]
                                for i in link_domain[2:]:
                                    link_full_path = link_full_path + '/' + i
                        else:
                            link_full_path = url.scheme + '://' + url.netloc
                        
                    except:
                        print 'error in setting link path'
                    link=verify_link(link)
                    if link <= 0:
                        continue
                    if debug:
                        print '\t\t\t\t\t> Link absolute path: {0}'.format(link)
                    
                except:
                    print '\t\t\t\t\t> Function verify_link() is not working'
                
                # We only add links not found yet
                if link not in allfiles:
                    allfiles.append(link)
                
                    if link not in crawled:
                        link_domain=urlparse.urlparse(link).netloc

                        # Here we verify that the link is associated to the main domain
                        if sub_domains:
                            accept=False
                            if accept_domain in link_domain:
                                accept=True
                        else:
                            accept=False
                            if link_domain == accept_domain:
                                accept=True
                            
                        if accept:
                            # Here we separate files URLs
                            if not link:
                                continue
                            if link not in link_to_files:
                                for ext in extensions:
                                    if link.endswith(ext):
                                        if link not in link_to_files:
                                            link_to_files.append(link)
                                            if debug:
                                                print '\t\t\t\t\t>> Found new link to file!: {0}'.format(link)
                                            break

                            # If after analysing the link it is not pointing to file we check it 
                            if link not in link_to_files:
                                # If the link is not already pending to crawl we add it 
                                if link not in URL:
                                    URL.append(link)
                                    if debug:
                                        print '\t\t\t\t\t>> Found new link!: {0}'.format(link)
                                else:
                                    if debug:
                                        print '\t\t\t\t> Seems that {0} already in URL'.format(link)
                                    continue
                        else:
                            if link not in externals and link != '/':
                                externals.append(link)
                                if debug and verbose:
                                    print '\t\t\t\t\t>> Found a external link: {0}'.format(link)
                            elif debug and verbose:
                                print '\t\t\t\t> External link: {0} already stored'.format(link)
                    else:
                        if debug:
                            print '\t\t\t\t> Link {0} already crawled'.format(link)
            else:
                if debug:
                    print '\t\t\t\t> Link \'{0}\' does not have enought lenght to be crawled'.format(link)
                                    

    except KeyboardInterrupt:
        return -2    
    except:
        return -3    

########################        
# CLEAN LINK
########################
def verify_link(link):
    """
    This function takes a link and verify if it has makers, mailto and feed references and return a cleaned link ready to analyze
    """
    global main_domain
    global host_name
    global url_scheme
    global link_full_path
    global emails
    global debug
    global verbose
    global splitters
    
    try:
        if debug:
            print '\t\t\t\t\t> Entering to verify_link function'
        for i in splitters:
            try:
                link.split(i)[1]
                link = link.split(i)[0]
                if debug and verbose:
                    print '\t\t\t\t> Link has a \'{0}\' reference. It has been removed.'.format(i)
                if link == "":
                    return -1
                break
            except:
                pass
    
        # Search for mailto references in LINK, check if email belongs to main domain and remove them to add it to crawl list if necessary.
        try:
            email=link.split('mailto:')[1]
            if debug and verbose:
                print '\t\t\t\t\t> Link have a "mailto:" reference. Email: {0}'.format(email)
            if (email.find(main_domain)!= -1):    
                try:
                    email.split('?')[1]
                    email = email.split('?')[0]
                except:
                    pass
                if email not in emails:
                    emails.append(email)
                if verbose and debug:
                    print '\n\t\t\t\t- Email found: {0}'.format(email),
            link=link.split('mailto:')[0]
        except:
            pass

        link_parsed = urlparse.urlparse(link)
        if link_parsed.scheme:
            return link
        
        #print 'Verifying link. Host Name: {0}, Main Domain: {1}, Url Scheme: {2}'.format(host_name,main_domain,url_scheme)

        # We well form the links starting with ../
        try:    
            link = link.split('../')[1]
            #print 'We well form the links starting with ../'
            #link = url_scheme+'://' + host_name + '/' + link
            link = url_scheme+'://' + main_domain + '/' + link
            if not link:
                return -2
            return link
        except:
            pass
        
        # We well form the links starting with ./
        try:
            link = link.split('./')[1]
            #print 'We well form the links starting with ./'
            #link = url_scheme+'://' + host_name + '/' + link
            link = url_scheme+'://' + main_domain + '/' + link
            if not link:
                return -2
            return link
        except:
            pass
        
        try:
            if link.startswith('//'):
                link = link.replace('/','',2)
                #print 'We well form the links starting with //'
                if not link:
                    return -1
                #link = url_scheme+'://' + host_name + link
                link = url_scheme+'://' + main_domain + '/' + link
                return link    
            if link.startswith('/'):
                link = link.replace('/','',1)
                #print 'We well form the links starting with /'
                if not link:
                    return -1
                if host_name.endswith('/'):
                    #link = url_scheme+'://' + host_name + link
                    link = url_scheme+'://' + main_domain + '/' + link
                else:
                    #link = url_scheme+'://' + host_name + '/' + link
                    link = url_scheme+'://' + main_domain + '/' + link
                return link    
        except:
            pass


        # Search for links with empty paths
        #if not link.startswith('/'):
        #if host_name.endswith('/'):
        #    link = url_scheme+'://' + host_name + link
        #else:
        #    link = url_scheme+'://' + host_name + '/' + link
        #print link_full_path
        if link_full_path.endswith('/'):
            link = link_full_path + link
        else:
            link = link_full_path + '/' + link

        #print link
        return link
    except:
        return -1

# IDENTIFY DIRECTORIES 
#########################
def identify_directories():

    """
    This function prints all the results found while crawling
    """
    
    global main_domain
    global host_name
    global crawled
    global directories
    global debug
    global verbose
    global url_scheme

    #Variables
    domain=url_scheme+'://'+host_name
    
    #Programa
    print '\n\t\t+ Searching for directories...'
    
    try:
        for link_url in crawled:
            try:
                if debug:
                    print '\t\t\t\t> Link extracted from "crawled": {0}'.format(link_url)
                # Here we eliminate error or status comments in URLs crawled.
                try:
                    link_url.split('(')[1]
                    link_url=link_url.split('(')[0]
                except:
                    pass
                
                # We store in tmp1 the complete path without domain
                link_directory_tmp1 = link_url.split(domain)[1]
                if debug:
                    print '\t\t\t\t> Path extracted form link: {0}'.format(link_directory_tmp1)
                
                # We separate the path to stay with last directory in it    
                link_directory_tmp2 = link_directory_tmp1.split('/')[1:-1]
                link_directory_tmp2.reverse()
                dir_tmp=""    
                while len(link_directory_tmp2)>0: 
                    dir_tmp=dir_tmp+link_directory_tmp2.pop()+'/'
                    link_directory = domain+'/'+dir_tmp
                    if link_directory not in directories:
                        directories.append(link_directory)    
                        print '\t\t\t- Found: {0}'.format(link_directory)
            except KeyboardInterrupt:
                try:
                    print '\t\t\t\t> Keyboard interrupt while iterating crawled vector. Waiting 1 seconds to continue.'
                    print '\t\t\t\t> Hit CTRL-C again to skip the rest of the URLs to analyze!'
                    time.sleep(1.5)
                    continue
                except KeyboardInterrupt:
                    return -4
            except:
                pass    

                    
        for link_url in link_to_files:
            try:
                if debug:
                    print '\t\t\t\t> Link extracted from "link_to_files": {0}'.format(link_url)

                # We store in tmp1 the complete path without domain
                link_directory_tmp1 = link_url.split(domain)[1]
                if debug:
                    print '\t\t\t\t> Path extracted form link: {0}'.format(link_directory_tmp1)
                
                # We separate the path to stay with last directory in it    
                link_directory_tmp2 = link_directory_tmp1.split('/')[1:-1]
                link_directory_tmp2.reverse()
                dir_tmp=""    
                while len(link_directory_tmp2)>0: 
                    dir_tmp=dir_tmp+link_directory_tmp2.pop()+'/'
                    link_directory = domain+'/'+dir_tmp
                    if link_directory not in directories:
                        directories.append(link_directory)    
                        print '\t\t\t- Found: {0}'.format(link_directory)
                    
            except KeyboardInterrupt:
                try:
                    print '\t\t\t\t> Keyboard interrupt while iterating crawled vector. Waiting 1 seconds to continue.'
                    print '\t\t\t\t> Hit CTRL-C again to skip the rest of the URLs to analyze!'
                    time.sleep(1.5)
                    continue
                except KeyboardInterrupt:
                    return -4
            except:
                pass

    except KeyboardInterrupt:
        print '\t\t\t\t> Keyboard interrupt while searching for directories! Exiting.'
        #sys.exit (1)
        return -6
    except:
        print '\t\t\t\t> Exception in looking for directories. Exiting.'
        #sys.exit (1)
        return -5


###################
# DIRECTORY LISTING
###################
def directory_indexing():
    """
    This function search for indexing in all directories already found and stored in directories.
    """

    global directories
    global directories_with_indexing
    global debug
    global crawl_results
    global URL
    global host_name
    global main_domain 
    global error_codes

    #Variables
    dir_response=""
    dir_msg=""
    URL=[]
    directory=""
    #Programa 

    try:
        # First we identify directories on site already crawled
        identify_directories()

        print '\t\t+ Searching open folders...',

        #Checking for directory indexing
        directories_with_indexing = []

        result={}
        for directory in directories:
            code=""
            dir_tmp=""
            try:
                if directory not in directories_with_indexing:
                    print '\n\t\t\t- {0}'.format(directory),
                    if debug: 
                        print '\n\t\t\t\t> Directory to analyze: {0}'.format(directory)
                    dir_response = urllib2.urlopen(directory.replace(' ','%20'))
                    dir_msg = dir_response.read()
                
                    if 'Index of' in dir_msg:
                        print '\n\t\t\t>>> Directory indexing at: {0}'.format(directory),
                        directories_with_indexing.append(directory)
                        result['DirIndex']=directory
                        a={}
                        a=copy.deepcopy(result)
                        crawl_results.append(a)
                        if debug:
                            print '\n\t\t\t\t> Directory appended to crawl_results',
                    else:
                        dir_tmp = directory+' (No open folder)'
                        directories[directories.index(directory)] = dir_tmp
                        print ' (No Open Folder)',
                
            except urllib2.HTTPError,error_code:
                code=error_codes[str(error_code.getcode())]
                print '({0})'.format(code),
                dir_tmp = directory+' ('+code+')'
                directories[directories.index(directory)] = dir_tmp

            except urllib2.URLError,error_code:
                print ' ({0})'.format(error_code.reason),
                dir_tmp = directory+' ('+error_code.reason+')'
                directories[directories.index(directory)] = dir_tmp
            except KeyboardInterrupt:
                try:
                    print '\n\t\t\t\t> Keyboard interrupt while looking for directory indexing. Waiting 1 seconds to continue.'
                    print '\t\t\t\t> Hit CTRL-C again to skip the rest of the URLs to analyze!',
                    time.sleep(1.5)
                    continue
                except KeyboardInterrupt:
                    return -5
            except:
                # If we are here is because not indexing in directory found
                dir_tmp = directory+' (No open folder)'
                directories[directories.index(directory)] = dir_tmp
                print ' (No Open Folder)',
                pass

        main_domain_tmp = main_domain
        host_name_tmp = host_name
        if directories_with_indexing.__len__() > 0:    
            print '\n\t\t+ Crawling directories with indexing:',
            for dir_tmp in directories_with_indexing:
                URL=[]
                #socket.setdefaulttimeout(30)
                dir_tmp_parsed = urlparse.urlparse(dir_tmp)
                main_domain = dir_tmp_parsed.netloc
                host_name = dir_tmp_parsed.netloc + dir_tmp_parsed.path
                
                result_crawl = crawl_url(dir_tmp)

            main_domain = main_domain_tmp
            host_name=host_name_tmp
            print '\n\t\t+ Crawling directories with indexing finished',
            return 1
    except KeyboardInterrupt:
        print '\n\t\t\t\t> Keyboard interrupt while searching for directory indexing! Exiting.'
        #sys.exit (1)
        return -9
    except:
        print '\n\t\t\t\t> Problems in searching for open folders or crawling again the folders with indexing.'


#############
# FETCH FILES 
#############
def fetch_files():

    """
    This function fetchs the files detected on the crawled domain in 'Files+domain' folder
    For now all files are stored in the same folder. No make any distinctions of directories.
    """

    global main_domain
    global link_to_files
    #global extensions_for_download 

    try:
        print '\n\t\t+ Fetching found files:'
        try:
            try:
                output_directory= main_domain.replace('http://','')
                output_directory= main_domain.replace('www.','')
                try:
                    output_directory = output_directory.split('/')[0]
                except:
                    pass
                try:
                    output_directory = output_directory.split(':')[0]
                except:
                    pass
            except:
                output_directory=main_domain
                pass
            os.mkdir(output_directory)
            output_directory = output_directory+'/Files/'
            os.mkdir(output_directory)

        except OSError,error:
            if 'File exists' in error:
                try:
                    if 'Files' in output_directory:
                        os.mkdir(output_directory)
                    else: 
                        output_directory = output_directory+'/Files/'
                        os.mkdir(output_directory)
                except OSError,error:
                    if 'File exists' in error:
                        print '\t\t> Output directory already exists! Overwriting content!'
                    else:
                        print '\t\t\t\t> Cannot create output directory! Not downloading files:'
                        return -15 

        print '\t\t\t- Files stored in: {0}'.format(output_directory)
        if verbose:
            print '\t\t\t- File extensions included:',
            for ext in extensions_for_download:
                if ext.islower():
                    print ext,
            print '\n'
        for i in link_to_files:
            for ext in extensions_for_download:
                if i.endswith(ext):
                    print '\t\t\t+ Downloading file {0}'.format(i)
                    error = fetch_file(i, output_directory)
                    if error == -1:
                        print '\t\t\t\t> Error saving file!'
                        pass
                    elif error == -11:
                        try:
                            print '\t\t\t\t> Keyboard interrupt while looking for directory indexing. Waiting 1 seconds to continue.'
                            print '\t\t\t\t> Hit CTRL-C again to skip the rest of the URLs to analyze!'
                            time.sleep(1.5)
                            pass
                        except KeyboardInterrupt:
                            return -5
                    elif error == -12:
                        print '\t\t\t\t> Exception in fetching file!'
                        pass
                    else:
                        pass
        return 1

    except:
        print '\t\t\t\t> Error in fetching files.'
        return -1

############
# FETCH FILE
############
def fetch_file(url_to_fetch,directory):
    
    """
    This function fetchs a single file from a given URL
    """
    
    global error_codes


    try:
        socket.setdefaulttimeout(50)
        web_file = urllib2.urlopen(url_to_fetch.replace(' ','%20'))
        
        try:
            local_file = directory+url_to_fetch.split('/')[-1]
            local_file = open(directory+url_to_fetch.split('/')[-1], 'w')
        except OSError, error:
            if 'File exists' in error:
                pass
            else:
                return -1
        local_file.write(web_file.read())
        local_file.close()
        return 1
    except urllib2.HTTPError,error_code:
        try:
            print '\t\t\t\t> ({0})'.format(error_codes[str(error_code.getcode())])
        except:
            print '\t\t\t\t> Error in requesting file'
        return -10    
    except urllib2.URLError,error_code:
        if debug:
            print '\t\t\t\t> ({0})'.format(error_code.reason)
        else:
            print '\t\t\t\t> ({0})'.format(error_code.reason)
    except KeyboardInterrupt:
        return -11
    except:
        return -12    

##########
# PRINTOUT
##########
def printout():

    """
    This function prints all the results found while crawling
    """
    
    global crawled
    global link_to_files
    global externals
    global allfiles
    global directories
    global emails
    global directories_with_indexing
    global host_name
    global url_scheme

    #Variables
    count=0

    try:
        print '----------------------------------------------------------------------'
        print 'Summary of ' + url_scheme + '://' + host_name
        print '----------------------------------------------------------------------'
        
        
        count=0
        print '+ Links crawled:'
        for i in crawled:
            print '\t- {0}'.format(i)
            count=count+1
        print '\tTotal links crawled: {0}'.format(count)

        count=0
        print '\n+ Links to files found:'
        for i in link_to_files:
            count=count+1
            print '\t- {0}'.format(i)
        print '\tTotal links to files: {0}'.format(count)

        count=0
        print '\n+ Externals links found:'
        for i in externals:
            print '\t- {0}'.format(i)
            count=count+1
        print '\tTotal external links: {0}'.format(count)
        
        
        """
        count=0
        print '\n+ All files found:'
        for i in allfiles:
            print '\t- {0}'.format(i)
            count=count+1
        print '\tTotal links: {0}'.format(count)
        """
        #Printing mails found
        count=0
        print '\n+ Email addresses found:'
        for mail in emails:
            print '\t- {0}'.format(mail)
            count=count+1
        print '\tTotal email address found: {0}'.format(count)

        
        #Printing directories found
        count=0
        print '\n+ Directories found:'
        for i in directories:
            print '\t- {0}'.format(i)
            count=count+1
        print '\tTotal directories: {0}'.format(count)
            

        #Printing directories with indexing activated
        count=0
        print '\n+ Directory indexing found:'
        for i in directories_with_indexing:
            print '\t- {0}'.format(i)
            count=count+1
        print '\tTotal directories with indexing: {0}'.format(count)
        
        print '\n----------------------------------------------------------------------\n'
        return 1

    except KeyboardInterrupt:
        print 'Keyboard Interrupt while printing! Exiting.'
        return -1
    except:
        return -2

##################
# PRINT TO FILE
##################
def print_to_file():

    """
    This function prints all the results found while crawling
    """
    
    global crawled
    global link_to_files
    global externals
    global allfiles
    global directories
    global emails
    global directories_with_indexing
    global host_name
    global main_domain

    try:
        try:
            output_directory= main_domain.replace('http://','')
            output_directory= main_domain.replace('www.','')
            try:
                output_directory = output_directory.split('/')[0]
            except:
                pass
            try:
                output_directory = output_directory.split(':')[0]
            except:
                pass

        except:
            output_directory=main_domain
            pass


        if debug: 
            print 'Output directory has been set: {0}'.format(output_directory)

        try:
            if debug: 
                print 'Creating output directory...'
            os.mkdir(output_directory)
        except OSError,error:
            if 'File exists' in error:
                if debug:
                    print '\t\t> Output directory already exists! Overwriting content!'
                pass
            else:
                print '\t\t\t\t> Cannot create output directory! Not downloading files:'
                return -15 
        
        # temp is the file name of the summary outout
        temp=host_name
        temp = temp.replace('http://','')
        temp = temp.replace('/','_')
        if debug: 
            print 'Saving file as: {0}/crawler_{1}'.format(output_directory,temp)
        f=open(output_directory+'/crawler_'+temp,'w')        
        f.writelines('--------------------------------------------------------------------\n')
        f.writelines('Sumary information of crawling site '+host_name+'\n')
        f.writelines('--------------------------------------------------------------------\n')

        count=0
        f.writelines('\n+ Links crawled:')
        for i in crawled:
            f.writelines('\n\t- '+i)
            count=count+1
        f.writelines('\n\tTotal links crawled: '+str(count)+'\n')

        count=0
        f.writelines('\n+ Links to files found:')
        for i in link_to_files:
            count=count+1
            f.writelines('\n\t- '+i)
        f.writelines('\n\tTotal links to files: '+str(count)+'\n')

        count=0
        f.writelines('\n+ Externals links found:')
        for i in externals:
            f.writelines('\n\t- '+i)
            count=count+1
        f.writelines('\n\tTotal external links: '+str(count)+'\n')
        
        
        #Printing mails found
        count=0
        f.writelines('\n+ Email addresses found:')
        for mail in emails:
            f.writelines('\n\t- '+mail)
            count=count+1
        f.writelines('\n\tTotal email address found: '+str(count)+'\n')

        
        #Printing directories found
        count=0
        f.writelines('\n+ Directories found:')
        for i in directories:
            f.writelines('\n\t- '+i)
            count=count+1
        f.writelines('\n\tTotal directories: '+str(count)+'\n')
            

        #Printing directories with indexing activated
        count=0
        f.writelines('\n+ Directory indexing found:')
        for i in directories_with_indexing:
            f.writelines('\n\t- '+i)
            count=count+1
        f.writelines('\n\tTotal directories with indexing: '+str(count)+'\n')

        f.close()

        return 1

    except KeyboardInterrupt:
        print 'Keyboard Interrupt while printing! Exiting.'
        return -1
    except:
        return -2
##########
# MAIN
##########
def main():
    try:
        global debug
        global verbose
        global write_to_file
        global fetch_files_opt
        global sub_domains
        global crawled
        global follow_redirect
        global main_domain
        global extensions_for_download

        base_url=""
        url_scheme=""
        extensions=""
        exclude_extensions=""
        # By default we crawl a max of 5000 distinct URLs
        max_amount_to_crawl=5000
        result =0    
        opts, args = getopt.getopt(sys.argv[1:], "hVDu:m:vwfsr[F:]d[E:]", ["help","version","debug","url=","deep=","verbose","write-to-file","fetch-files","subdomains",'follow-redirect','file-extension','docs-files','exclude-extensions'])


    except getopt.GetoptError: usage()    

    for opt, arg in opts:
        if opt in ("-h", "--help"): usage()
        if opt in ("-v", "--verbose"): verbose=True
        if opt in ("-u", "--url"): base_url=arg
        if opt in ("-m", "--max_amount_to_crawl"): max_amount_to_crawl=arg
        if opt in ("-f", "--fetch-files"): fetch_files_opt=True; extensions="doc,ppt,pps,xls,docx,pptx,ppsx,xlsx,sxw,sxc,sxi,odt,ods,odg,odp,pdf,wpd,txt,gnumeric,csv,asc,sql,rar,mdb,jar,mp3,sty,jpg,jpeg,png,gif,exe,py,zip,tar,gz,bz,bmp"
        if opt in ("-V", "--version"): version();exit(1)
        if opt in ("-D", "--debug"): debug=True
        if opt in ("-w", "--write-to-file"): write_to_file=True
        if opt in ("-s", "--subdomains"): sub_domains=True
        if opt in ("-r", "--follow-redirect"): follow_redirect=False
        if opt in ("-F", "--file-extension"): fetch_files_opt=True; extensions=arg
        if opt in ("-E", "--exclude-extensions"): exclude_extensions=arg;
    
        if opt in ("-d", "--docs-files"):fetch_files_opt=True; extensions="doc,ppt,pps,xls,docx,pptx,ppsx,xlsx,sxw,sxc,sxi,odt,ods,odg,odp,pdf,wpd,txt,gnumeric,csv"

    try:
        if base_url != "":
            version()

            if extensions:
                extensions_for_download=[]
                for i in extensions.split(',')[0:]:
                    if not i.startswith('.'):
                        extensions_for_download.append('.'+i.upper())
                        extensions_for_download.append('.'+i.lower())
                    else:
                        extensions_for_download.append(i.upper())
                        extensions_for_download.append(i.lower())

            if exclude_extensions:
                for i in exclude_extensions.split(',')[0:]:
                    i='.'+i
                    if i.lower() in extensions_for_download:
                        extensions_for_download.remove(i.lower())
                        extensions_for_download.remove(i.upper())

            
            # We decrement the value by 1 because we count the 0
            result = crawl_site(base_url,int(max_amount_to_crawl))

            if result == -1:
                if follow_redirect and crawled:
                    redirect = crawled[0] 
                    if not redirect.split(' ')[-1].split(')')[0].startswith('http://'):
                        redirect_link = redirect.split(' ')[0] + '/' + redirect.split(' ')[-1].split(')')[0]
                    else:
                        redirect_link = redirect.split(' ')[-1].split(')')[0]
                    if crawled[0] != redirect_link and main_domain != urlparse.urlparse(redirect_link).netloc:
                        print '\t+ Following redirection at:: {0}\n'.format(redirect_link)
                        if debug:
                            print '\t\t- URL: {0}, Redirection: {1}'.format(redirect.split(' ')[0],redirect.split(' ')[-1].split(')')[0])
                        result = crawl_site(redirect_link,int(max_amount_to_crawl)+1)
                    else:
                        printout()
                else:
                    printout()
            #else:
            #    print 'Problems with the URL. Checkit.'
        else:
            usage()
        
    except KeyboardInterrupt:
        # CTRL-C pretty handling
        print 'Keyboard Interruption!. Exiting.'
        sys.exit(1)


if __name__ == '__main__':
    main()
