import re
from ciscoconfparse import CiscoConfParse # pip install ciscoconfparse
from netaddr import IPAddress
from netaddr import IPNetwork
import type7 # modified version of https://github.com/theevilbit/ciscot7/blob/master/ciscot7.py

#Files to eval
files = ['file1.config', 'file2.config']

####Regex
bgpPeerGroup = re.compile('.*? neighbor [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} peer-group .*')
ipAddress = re.compile('.* ip address [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}.*')
secondaryIP = re.compile('.* ip address [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}.*? secondary')
ipv6Address = re.compile('.* ipv6 address (([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))')
ipv6Neighbor = '(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))'

def type7Decode(string):
    return type7.autodecrypt(string)

def newRouteMap(routemap,aspathid,asn):
    replaced = string.replace('match as-path ' + aspathid, 'match as-path AS_' + asn)
    return replaced

def getBGP_NeighborASGlobal(parse,neighbor):
    bgpconfig = parse.find_objects('^router bgp.*')
    for obj in bgpconfig:
        if obj.re_search_children(r'.*neighbor '+neighbor+' remote-as .*'):
            for child in obj.re_search_children(r'.*neighbor '+neighbor+' remote-as .*'):
                peerASpre = child.text
                peerAS = peerASpre.replace(' neighbor '+neighbor+' remote-as ','')
                return peerAS
        else:
            child = obj.re_search_children(r'.*neighbor '+neighbor+' peer-group .*')
            peergrouppre = child[0].text
            peergroup = peergrouppre.replace(' neighbor '+neighbor+' peer-group ','')
            if peergroup:
                for child in obj.re_search_children(r'.*neighbor ' + peergroup + ' remote-as .*'):
                    peerASpre = child.text
                    peerAS = peerASpre.replace(' neighbor ' + peergroup + ' remote-as ','')
                    return peerAS

def filterGet(parse,neighbor):
    bgpconfig = parse.find_objects('^router bgp.*')
    ipv4config = parse.find_objects('.*address-family ipv4')
    ipv6config = parse.find_objects('.*address-family ipv6')
    if bgpconfig[0].re_search_children(r'.*neighbor '+neighbor+' filter-list .*'):
        filterpre = bgpconfig[0].re_search_children(r'.*neighbor '+neighbor+' filter-list .*')[0].text
        filterlist = filterpre.split(' ')
    elif ipv4config[0].re_search_children(r'.*neighbor '+neighbor+' filter-list .*'):
        filterpre = ipv4config[0].re_search_children(r'.*neighbor '+neighbor+' filter-list .*')[0].text
        filterlist = filterpre.split(' ')
    elif ipv6config[0].re_search_children(r'.*neighbor '+neighbor+' filter-list .*'):
        filterpre = ipv6config[0].re_search_children(r'.*neighbor '+neighbor+' filter-list .*')[0].text
        filterlist = filterpre.split(' ')
    else:
        return
    filterid = filterlist[5]
    return filterid

def filterConvert(string,aspathid,asn):
    replaced = string.replace('ip as-path access-list '+aspathid,'ip as-path access-list AS_'+asn)
    return replaced

def getBGP_NeighborRouteMap(parse,neighbor):
    bgpconfig = parse.find_objects('^router bgp.*')
    ipv4config = parse.find_objects('.*address-family ipv4')
    ipv6config = parse.find_objects('.*address-family ipv6')
    if bgpconfig[0].re_search_children(r'.*neighbor '+neighbor+' route-map .* in'):
        rmpre = bgpconfig[0].re_search_children(r'.*neighbor '+neighbor+' route-map .* in')[0].text
        rmlist = rmpre.split(' ')
    elif ipv4config[0].re_search_children(r'.*neighbor '+neighbor+' route-map .* in'):
        rmpre = ipv4config[0].re_search_children(r'.*neighbor '+neighbor+' route-map .* in')[0].text
        rmlist = rmpre.split(' ')
    elif ipv6config[0].re_search_children(r'.*neighbor '+neighbor+' route-map .* in'):
        rmpre = ipv6config[0].re_search_children(r'.*neighbor '+neighbor+' route-map .* in')[0].text
        rmlist = rmpre.split(' ')
    else:
        return
    return rmlist[5]

for file in files:
    parse = CiscoConfParse(file)
    routeMapDict = {}
    iflist = {}
    # find interfaces
    interfaces = parse.find_objects('^interface ')
    hostnameregex = parse.find_objects('^hostname (.*)')
    #get hostname
    for item in hostnameregex:
        hostname = item.text
        hostname = hostname.strip('hostname')
        hostname = hostname.strip()
    #get interface IP addressing
    #print '-------------Interfaces--------------'
    for obj in interfaces:
         if obj.re_search_children(r"ip address [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}.*"):
             ifname = obj.text.strip('interface ')
             iplist = []
             secondarylist = []
             ipv6list = []
             for child in obj.children:
                 if secondaryIP.match(child.text):
                     rawIP = child.text.strip(' ip address ')
                     splitIP = rawIP.split(' ')
                     cidrIP = splitIP[0]+'/'+str(IPAddress(splitIP[1]).netmask_bits())
                     secondarylist.extend([cidrIP])
                 elif ipAddress.match(child.text):
                     rawIP = child.text.strip(' ip address ')
                     splitIP = rawIP.split(' ')
                     cidrIP = splitIP[0]+'/'+str(IPAddress(splitIP[1]).netmask_bits())
                     iplist.extend([cidrIP])
                 elif ipv6Address.match(child.text):
                     rawIP = child.text.strip(' ipv6 address ')
                     cidrIPv6 = rawIP
                     ipv6list.extend([cidrIPv6])
             iflist.update({ifname:{'PrimaryIP': iplist,'SecondaryIPs': secondarylist,'IPv6IPs': ipv6list }})
        #print iflist[intf]
    #get ipv4 static routes
    #print '-------------v4_Static_Routes--------------'
    v4routes = []
    routes = parse.find_objects('^ip route .*')
    for obj in routes:
        v4routes.append(obj.text)
    #get ipv6 static routes
    #print '-------------v6_Static_Routes--------------'
    v6routes = []
    routes = parse.find_objects('^ipv6 route .*')
    for obj in routes:
        v6routes.append(obj.text)
    #get community-lists
    #print '-------------Community_Lists--------------'
    comms = []
    commlist = parse.find_objects('^ip community-list.*')
    for obj in commlist:
        comms.append(obj.text)
    #get as-path access-lists
    #print '-------------AS_Path_Lists--------------'
    aspathlist = []
    newaspathlist = []
    aspath = parse.find_objects('^ip as-path access-list.*')
    for obj in aspath:
        badaspath = re.match(r'(.*ip as-path access-list [0-9]{1,4} permit .*) (.*)', obj.text)
        if badaspath:
            newaspath = badaspath.group(1)+'_'+badaspath.group(2)
        else:
            newaspath = obj.text
        aspathlist.append(newaspath)
    #get ipv4 prefix-lists
    #print '-------------v4-Prefix-Lists--------------'
    ipv4Prefixlists = []
    prefixlist = parse.find_objects('^ip prefix-list .*')
    for obj in prefixlist:
        if re.match(r'.* description.*',obj.text):
            pass
        else:
            stripSeqNo = re.match(r'.*( seq [0-9]{1,4}) .*',obj.text)
            newtext = obj.text.replace(stripSeqNo.group(1),'')
            ipv4Prefixlists.append(newtext)

    #get ipv6 prefix-lists
    #print '-------------v6-Prefix-Lists--------------'
    ipv6Prefixlists = {}
    ipv6PLidList = []
    allPLLines = []
    prefixlist = parse.find_objects('^ipv6 prefix-list .*')
    for obj in prefixlist:
        PLid = re.match(r'(.*ipv6 prefix-list .*) (seq.*)', obj.text)
        PLparent = PLid.group(1)
        PLLine = PLid.group(2)
        if PLid.group(1) in ipv6Prefixlists:
            ipv6Prefixlists[PLid.group(1)].append(' '+PLLine)
        else:
            ipv6Prefixlists.update({PLid.group(1):[' '+PLLine]})
    #get access-lists
    #print '-------------Access-Lists--------------'
    aclList = {}
    aclList2 = []
    aclidList = []
    secondaryAcl = []
    extAcl = parse.find_objects('.*ip access-list extended.*')
    for obj in extAcl:
        if re.match('.*ip access-list extended.*', obj.text):
            aclList2.append(obj.text)
            for item in obj.children:
                aclList2.append(item.text)
    acl = parse.find_objects('^access-list .*')
    for obj in acl:
        aclid = re.match(r'.*access-list ([0-9]{1,4}) (.*)',obj.text)
        if 1 <= int(aclid.group(1)) <= 99 or 1300 <= int(aclid.group(1)) <= 1999:
            newAcl = 'ip access-list standard '+aclid.group(1)
        else:
            newAcl = 'ip access-list '+aclid.group(1)
        aclLine = aclid.group(2)
        aclProcessed = re.match(r'(.*permit )([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})$',aclLine)
        if aclProcessed:
            fixedACL = aclProcessed.group(1)+' host '+aclProcessed.group(2)
        else:
            fixedACL = aclLine
        if newAcl in aclList:
            aclList[newAcl].append(' '+fixedACL)
        else:
            aclList.update({newAcl:[' '+fixedACL]})
    #get route-maps
    #print '-------------Route-Maps--------------'
    routemap = parse.find_objects('^route-map .*')
    for obj in routemap:
        routeMapName = obj.text
        routeMapInfo = re.match(r'.*route-map (.*) [aA-zZ].* ([0-9]{1,4})',obj.text)
        routeMapShort = routeMapInfo.group(1)+'_'+routeMapInfo.group(2)
        routeMapLine = []
        for child in obj.children:
            if re.match('.*match as-path [0-9]{1,4} [0-9]{1,4}.*',child.text):
                # EOS doesn't accept multiple AS-Path ACLs. Convert to single list.
                # To-Do - right now I merge two lists. Need to add logic to split
                #   into multiple route-map entries with different lists.
                aspathlistpre = re.match('(.*match as-path (.*))',child.text)
                aspathparsed = aspathlistpre.group(2).split(' ')
                newaspathLines = []
                for item in aspathparsed:
                    for asid in aspathlist:
                        if re.match(r'.*ip as-path access-list '+item+'.*',asid):
                            asinfo = re.match(r'.*ip as-path access-list ' + item + '(.*)', asid)
                            newaspathlist.append('ip as-path access-list '+routeMapShort+asinfo.group(1))
                routeMapLine.append(' match as-path '+routeMapShort)
            elif re.match(r'.*match ip address [0-9]{1,4}$', child.text):
                routeMapLine.append(child.text.replace('match ip address', 'match ip address access-list'))
            elif re.match(r'.*match ip address [0-9]{1,4} .*',child.text):
                # EOS doesn't accept multiple ACLs. Convert to single list.
                acllistpre = re.match('(.*match ip address ([0-9]{1,4}.*))', child.text)
                acllistparsed = acllistpre.group(2).split(' ')
                newaclLines = []
                storedlines = []
                for item in acllistparsed:
                    for aclid in list(aclList.keys())[:]:
                        if re.match(r'.*ip access-list standard '+item,aclid):
                            aclname = re.match(r'.*(ip access-list standard ).*',aclid).group(1)
                            for line in aclList[aclid]:
                                storedlines.append(line)
                        elif re.match(r'.*ip access-list '+item+'.*',aclid):
                            aclname = re.match(r'.*(ip access-list ).*', aclid).group(1)
                            for line in aclList[aclid]:
                                storedlines.append(line)
                    aclList.update({aclname+routeMapShort: storedlines})
                routeMapLine.append(' match ip address access-list ' + routeMapShort)
            elif re.match(r'.*match ip address prefix-list .* .*', child.text):
                # EOS doesn't accept multiple Prefix-lists. Convert to single list.
                prefixlistpre = re.match('(.*match ip address prefix-list (.*))', child.text)
                plparsed = prefixlistpre.group(2).split(' ')
                newPLLines = []
                for item in plparsed:
                    for PLid in ipv4Prefixlists:
                        if re.match(r'.*ip prefix-list ' + item + '.*', PLid):
                            asinfo = re.match(r'.*ip prefix-list ' + item + '(.*)', PLid)
                            ipv4Prefixlists.append('ip prefix-list ' + routeMapShort + asinfo.group(1))
                routeMapLine.append(' match ip address prefix-list ' + routeMapShort)
            elif re.match(r'.*match ip address prefix-list .*',child.text):
                routeMapLine.append(child.text)
            elif re.match(r'.*match ip address (.*)',child.text):
                routeMapLine.append(child.text.replace('match ip address', 'match ip address access-list'))
            else:
                routeMapLine.append(child.text)
            routeMapDict.update({routeMapName: routeMapLine})
    #get OSPF Config
    ospflist = []
    ospfconfig = parse.find_objects('^router ospf.*')
    ospfid = ospfconfig[0].text
    ospflist.append(ospfid)
    for child in ospfconfig[0].children:
        ospflist.append(child.text)
    v6ospflist = []
    v6ospfconfig = parse.find_objects('^ipv6 router ospf.*')
    ospfid = v6ospfconfig[0].text
    v6ospflist.append(ospfid)
    for child in v6ospfconfig[0].children:
        v6ospflist.append(child.text)
    for item in ospflist[:]:
        if re.match('.*traffic-share min across-interfaces',item):
            ospflist.remove(item)
        elif re.match('.*redistribute .* subnets', item):
            newitem = item.replace(' subnets','')
            ospflist.remove(item)
            ospflist.append(newitem)
    #get BGP neighbors
    #print '-------------BGP Neighbors--------------'
    bgpconfig = parse.find_objects('^router bgp.*')
    bgpASpreparse = bgpconfig[0].text
    bgpAS = bgpASpreparse.strip('router bgp ')
    bgplist = []
    bgpaflist = []
    bgplist.append(bgpASpreparse)
    for item in bgpconfig[0].all_children:
        bgplist.append(item.text)
    for item in bgplist[:]:
        if re.match(r'.*address-family ipv4',item):
            bgpaflist.append(item)
            bgplist.remove(item)
        elif re.match(' address-family ipv6',item):
            bgpaflist.append(item)
            bgplist.remove(item)
        elif re.match(r'.*neighbor .* activate',item):
            bgpaflist.append(item)
            bgplist.remove(item)
        elif re.match(r'.*neighbor .*? version 4',item):
            bgplist.remove(item)
        elif re.match(r'.*neighbor .*? password 7 .*',item):
            encryptedpass = re.match(r'(.*neighbor .*? password )7 (.*)',item)
            decryptedpass = type7Decode(encryptedpass.group(2))
            bgplist.append(encryptedpass.group(1)+decryptedpass)
            bgplist.remove(item)
        elif re.match(r'.*no auto-summary', item):
            bgplist.remove(item)
        elif re.match(r'.*no synchronization',item):
            bgplist.remove(item)
        elif re.match(r'.*exit-address-family',item):
            bgplist.remove(item)
        elif re.match(r'.*bgp deterministic-med',item):
            bgplist.remove(item)
        elif re.match(r'.*bgp maxas-limit.*',item):
            bgplist.remove(item)
        elif re.match(r'.*neighbor .* filter-list .*',item):
            bgplist.remove(item)
        elif re.match(r'.*no bgp default ipv4-unicast',item):
            bgplist.remove(item)
        elif re.match(r'.*bgp confederation identifier .*',item):
            bgplist.remove(item)
        elif re.match(r' bgp confederation peers.*',item):
            bgplist.remove(item)
        elif re.match(r'.*!',item):
            bgplist.remove(item)
        elif re.match(r'.*network [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} route-map.*',item):
            parsed = re.match(r'(.*network ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) route-map.*)',item)
            newIP = IPNetwork(parsed.group(2),implicit_prefix=True)
            bgplist.remove(item)
            newitem = item.replace(parsed.group(2),str(newIP))
            bgplist.append(newitem)
        elif re.match(r'.*neighbor.* maximum-prefix .*',item):
            bgplist.remove(item)
            newitem = item.replace(' maximum-prefix ',' maximum-routes ')
            maxwarn = re.match(r'(.* neighbor .* maximum-routes [0-9]{1,7} )(.*)',newitem)
            if maxwarn:
                newitem = maxwarn.group(1)+'warning-limit '+maxwarn.group(2)+' percent'
            bgplist.append(newitem)
    for obj in bgpconfig:
        if obj.re_search_children(r'.*neighbor .*? remote-as .*'):
            for child in obj.re_search_children(r'.*neighbor .*? remote-as .*'):
                childlist = child.text.split(' ')
                filterresult = filterGet(parse,childlist[2])
                if filterresult:
                    asid = getBGP_NeighborASGlobal(parse,childlist[2])
                    aspathid = parse.find_objects('^ip as-path access-list '+filterresult)
                    for obj in aspathid:
                        converted = filterConvert(obj.text,filterresult,asid)
                        aspathlist = [a.replace(obj.text,converted) for a in aspathlist]
                    routemaps = getBGP_NeighborRouteMap(parse,childlist[2])
                    for item in routeMapDict:
                        popList = []
                        popKey = {}
                        if re.match(r'route-map '+routemaps+' permit ',item):
                            for subitem in routeMapDict[item]:
                                if re.match(r'.*match as-path.*',subitem):
                                    subitem = subitem.replace('match as-path ' + filterresult, 'match as-path AS_' + asid)
                                    popList.append(subitem)
                                else:
                                    popList.append(subitem)
                            popKey.update({item:popList})
                            routeMapDict.pop(item)
                            routeMapDict.update(popKey)

    with open(hostname + '.txt', 'w') as f:
        configlet = []
        configlet.append('!--------------Hostname--------------')
        configlet.append('hostname ' + hostname)
        configlet.append('!')
        configlet.append('!-------------Interfaces---------------')
        for intf in iflist.keys():
            configlet.append('interface ' + intf)
            for item in iflist[intf]['PrimaryIP']:
                configlet.append('   ip address ' + item)
            if len(iflist[intf]['SecondaryIPs']) > 0:
                for item in iflist[intf]['SecondaryIPs']:
                    configlet.append('   ip address ' + item + ' secondary')
            if len(iflist[intf]['IPv6IPs']) > 0:
                for item in iflist[intf]['IPv6IPs']:
                    configlet.append('   ipv6 address ' + item)
        configlet.append('!')
        configlet.append('!-----------------ACLs---------------')
        for item in aclList:
            configlet.append(item)
            for subitem in aclList[item]:
                configlet.append(subitem)
        for item in aclList2:
            configlet.append(item)
        configlet.append('!')
        configlet.append('!------------AS-Path-Lists-----------')
        for item in aspathlist:
            configlet.append(item)
        for item in newaspathlist:
            configlet.append(item)
        configlet.append('!')
        configlet.append('!-----------Prefix-Lists-----------')
        for item in ipv4Prefixlists:
            configlet.append(item)
        for item in ipv6Prefixlists:
            configlet.append(item)
            for subitem in ipv6Prefixlists[item]:
                configlet.append(subitem)
        configlet.append('!')
        configlet.append('!----------Community List---------')
        for item in comms:
            configlet.append(item)
        configlet.append('!')
        configlet.append('!---------NewRouteMaps------------')
        for item in routeMapDict:
            configlet.append(item)
            for subitem in routeMapDict[item]:
                configlet.append(subitem)
        configlet.append('')
        configlet.append('!')
        configlet.append('!------------Static Routes-----------')
        for item in v4routes:
            configlet.append(item)
        configlet.append('!')
        for item in v6routes:
            configlet.append(item)
        configlet.append('!')
        configlet.append('!------------Router OSPF-------------')
        for item in ospflist:
            configlet.append(item)
        for item in v6ospflist:
            configlet.append(item)
        configlet.append('!')
        configlet.append('!------------Router BGP--------------')
        for item in bgplist:
            configlet.append(item)
        for item in bgpaflist:
            configlet.append(item)
        for item in configlet:
            f.write(item)
            f.write('\n')
        f.close
