from pyroute2 import IPRoute, netns

if __name__ == '__main__':
    # create two namespaces for root and sub CA.
    netns.create('Root CA')
    netns.create('Sub CA')
    
    # get access to the netlink socket
    ipr = IPRoute()
    
    # create a virtual ethernet interface pair for every CA
    ipr.link('add', ifname='veth-rt', peer='veth-sub', kind='veth')
    # wait for the devices creation application
    veth_rt, veth_sub = ipr.poll(
        ipr.link, 'dump', timeout=5, ifname=lambda x: x in ('veth-rt', 'veth-sub')
    )
    # assure that the variable's name is coresponding to the interface.
    if veth_rt.get_attr('IFLA_IFNAME') != 'veth-rt':
        veth_rt, veth_sub = veth_sub, veth_rt

    # set the state of interfaces for root and sub to UP, make it work
    ipr.link('set', index=veth_rt['index'], state='up')
    ipr.link('set', index=veth_sub['index'], state='up')
    # assign IP addr for every interface
    ipr.addr('add', index=veth_rt['index'], address='192.168.0.1', prefixlen=24)
    ipr.addr('add', index=veth_sub['index'], address='192.168.0.2', prefixlen=24)
    
    # plug the interface into the coresponding namespace.
    # 
    # Note that, you have no visibility to the veth any more, 'cause it
    # has belonged to the specific namespace.
    ipr.link('set', index=veth_rt['index'], net_ns_fd='Root CA')
    ipr.link('set', index=veth_sub['index'], net_ns_fd='Sub CA')
    
    # BTW, don't forget realse the resource of IPRoute.
    ipr.close()
    
    # So, you may find that, it's no need to delete the veth interfaces.
    # But, if you didn't put any veth into a namespace, you'd better use
    # `ipr.link('del', ifname='to_be_deleted')` to delete it.
    #
    # The statements below remove namespaces for root and sub CA.
    netns.remove('Sub CA')
    netns.remove('Root CA')