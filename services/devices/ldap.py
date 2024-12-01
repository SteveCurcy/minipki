class LDAP:
    def __init__(self) -> None:
        # This is used to save the dict from cert's SN to its status.
        self.status = set()
    
    def update(self, sn: int) -> None:
        self.status.add(sn)
    
    def get(self, sn: int) -> bool:
        return sn in self.status
    
    def delete(self, sn: int) -> None:
        self.status.remove(sn)
