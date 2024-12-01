from devices import LDAP

class OCSP:
    def __init__(self, ldap: LDAP) -> None:
        self.__ldap = ldap
    
    def fresh(self, sn: int) -> None:
        self.__ldap.update(sn)
    
    def expire(self, sn: int) -> None:
        self.__ldap.delete(sn)
    
    def check(self, sn: int) -> bool:
        return self.__ldap.get(sn)
