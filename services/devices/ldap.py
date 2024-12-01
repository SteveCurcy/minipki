class LDAP:
    def __init__(self) -> None:
        # This is used to save the dict from cert's SN to its status.
        self.status = set()
    
    def update(self, sn: str) -> None:
        self.status.add(sn)
    
    def get(self, sn: str) -> bool:
        return sn in self.status
    
    def delete(self, sn: str) -> None:
        self.status.remove(sn)
