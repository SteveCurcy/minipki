from pyroute2 import IPRoute, netns, NetNS, IPDB
from multiprocessing import Process
import socket
import time
import os

def tls_server():
    netns.setns('Root')
    
    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Bind the socket to the address and port
    server_socket.bind(('192.168.0.1', 233))
    server_socket.listen(1)  # Allow up to 5 pending connections
    print(f"[MiniPKI] Server: listening on 192.168.0.1:233.")

    # Accept a new connection
    client_socket, client_address = server_socket.accept()
    print(f"[MiniPKI] Server: connected by {client_address}.")

    # Receive a message
    data = client_socket.recv(1024)
    print(f"[MiniPKI] Server: Received \"{data.decode()}\".")

    # Send a response
    client_socket.send(b"Hello, Client!")
    client_socket.close()

if __name__ == '__main__':
    if os.path.exists('/var/run/netns/Root'):
        netns.remove('Root')
        netns.remove('Sub')
    # create two namespaces for root and sub.
    netns.create('Root')
    netns.create('Sub')
    
    # get access to the netlink socket
    ipr = IPRoute()
    
    # create a virtual ethernet interface pair for every ns
    ipr.link('add', ifname='veth-rt', peer='veth-sub', kind='veth')
    # wait for the devices creation application
    veth_rt, veth_sub = ipr.poll(
        ipr.link, 'dump', timeout=5, ifname=lambda x: x in ('veth-rt', 'veth-sub')
    )
    # assure that the variable's name is coresponding to the interface.
    if veth_rt.get_attr('IFLA_IFNAME') != 'veth-rt':
        veth_rt, veth_sub = veth_sub, veth_rt
    
    # plug the interface into the coresponding namespace.
    # 
    # Note that, you have no visibility to the veth any more, 'cause it
    # has belonged to the specific namespace.
    ipr.link('set', index=veth_rt['index'], net_ns_fd='Root')
    ipr.link('set', index=veth_sub['index'], net_ns_fd='Sub')
    
    ns_rt = NetNS('Root')
    (veth_rt, ) = ns_rt.poll(
        ns_rt.link, 'dump', timeout=5, ifname=lambda x: x.startswith('veth-rt')
    )

    # set the state of interfaces for root and sub to UP, make it work
    ns_rt.link('set', index=veth_rt['index'], state='up')
    # assign IP addr for every interface
    ns_rt.addr('add', index=veth_rt['index'], address='192.168.0.1', prefixlen=24)
    
    ns_sub = NetNS('Sub')
    (veth_sub, ) = ns_sub.poll(
        ns_sub.link, 'dump', timeout=5, ifname=lambda x: x.startswith('veth-sub')
    )
    
    ns_sub.link('set', index=veth_sub['index'], state='up')
    ns_sub.addr('add', index=veth_sub['index'], address='192.168.0.2', prefixlen=24)
    
    ns_rt.close()
    ns_sub.close()
    del ns_sub
    del ns_rt
    # netns.setns('/proc/1/ns/net')   # go back to default netns
    
    process = Process(target=tls_server)
    process.start()
    time.sleep(1)
    
    # Save the current netns in order to return to it later. If newns
    # is specified, change to it.
    # netns.pushns('Sub')
    
    netns.setns('Sub')

    # Create a standard TCP socket
    c_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Connect to the server
    # **NOTE**: You must use method connect_ex(), but not connect().
    # There may be some bugs makes the client namespace cannot find
    # the server namespace, which occurs error 'Host is unreachable'.
    result = c_socket.connect_ex(('192.168.0.1', 233))
    if result == 0:
        print(f"[MiniPKI] Client: connected to 196.168.0.1:233.")
    else:
        print(f"[MiniPKI] Error: failed to connect to 196.168.0.1:233.")

    # Send a message
    c_socket.send(b"Hello, Server!")
    print("[MiniPKI] Client: Message sent!")

    # Receive a response
    response = c_socket.recv(1024)
    print(f"[MiniPKI] Client: Received \"{response.decode()}\".")
    
    process.join()
    
    # Restore the previously saved netns. No use, just for learning.
    # netns.popns()
    
    # BTW, don't forget realse the resource of IPRoute.
    ipr.close()
    del ipr
    
    # So, you may find that, it's no need to delete the veth interfaces.
    # But, if you didn't put any veth into a namespace, you'd better use
    # `ipr.link('del', ifname='to_be_deleted')` to delete it.
    #
    # The statements below remove namespaces for root and sub.
    netns.remove('Sub')
    netns.remove('Root')