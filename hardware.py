"""
This module provides some hardware classes to create a client, server,
switch and router. The classes are used to create a network topology.
"""
import multiprocessing
from pyroute2 import netns, IPRoute
import os

class Hardware():
  veth_prefix = 0
  veth_suffix = 0

  SHUTDOWN = 0
  RUNNING = 1

  # set the lock as a class variable
  lock = multiprocessing.Lock()
  condition = multiprocessing.Condition(lock)

  @staticmethod
  def get_next_veth_name() -> str:
    next_name = f"v{Hardware.veth_prefix}p{Hardware.veth_suffix}"
    Hardware.veth_suffix += 1
    if Hardware.veth_suffix > 1024:
      Hardware.veth_suffix = 0
      Hardware.veth_prefix += 1
    return next_name
  
  def __init__(self, name: str):
    netns.create(name)
    self._name = name
    self._pid = None
    self._interfaces = []
    self._status = multiprocessing.Value('i', Hardware.RUNNING)
    self._process = multiprocessing.Process(target=Hardware.run, args=(self, ), name=name)
    self._process.start()

  def run(self):
    self._pid = os.getpid()
    netns.pushns(self._name)
    self.work()
    netns.popns()

  def work(self):
    while self._status == Hardware.RUNNING:
      pass
  
  def link_to(self, other, addr1: str = None, addr2: str = None):
    if isinstance(other, Hardware):
      connect_hws(self, other, addr1, addr2)

  def shutdown(self):
    self._status = Hardware.SHUTDOWN
    self._process.join()
    netns.remove(self._name)

@staticmethod
def connect_hws(hw1: Hardware, hw2: Hardware, addr1: str = None, addr2: str = None):
  # create a veth pair and move it to each namespace
  ipr = IPRoute()

  # create a veth pair and get the object of each veth
  # NOTE: Use assert command to check if the veth pair is created successfully
  veth_name1 = Hardware.get_next_veth_name()
  veth_name2 = Hardware.get_next_veth_name()
  ipr.link('add', ifname=veth_name1, peer=veth_name2, kind='veth')
  veth1 = ipr.poll(ipr.link, 'dump', timeout=5, ifname=veth_name1)
  veth2 = ipr.poll(ipr.link, 'dump', timeout=5, ifname=veth_name2)
  assert (len(veth1) == 1 and len(veth2) == 1), "Failed to create veth pair"
  veth1, veth2 = veth1[0], veth2[0]

  # set the veth status to up and move it to the respective namespace
  ipr.link('set', index=veth1.get('index'), state='up', net_ns_fd=hw1._name)
  ipr.link('set', index=veth2.get('index'), state='up', net_ns_fd=hw2._name)
  hw1._interfaces.append(veth_name1)
  hw2._interfaces.append(veth_name2)

  if addr1:
    netns.pushns(hw1._name)
    hw1_ipr = IPRoute()
    hw1_ipr.addr('add', index=veth1.get('index'), address=addr1, mask=24)
    hw1_ipr.close()
    netns.popns()
  if addr2:
    netns.pushns(hw2._name)
    hw2_ipr = IPRoute()
    hw2_ipr.addr('add', index=veth2.get('index'), address=addr2, mask=24)
    hw2_ipr.close()
    netns.popns()

  ipr.close()

if __name__ == '__main__':
  # Example usage
  hw1 = Hardware('hw1')
  hw2 = Hardware('hw2')
  connect_hws(hw1, hw2, '10.0.0.1', '10.0.0.2')
  hw1.shutdown()
  hw2.shutdown()
