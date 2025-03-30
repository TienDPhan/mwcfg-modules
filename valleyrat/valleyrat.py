import logging
from malduck.extractor import Extractor

log = logging.getLogger(__name__)

__author__ = "Tien.D.Phan"
__version__ = "1.0.0"


class ValleyRAT(Extractor):

    """
    ValleyRAT Configuration Extractor
    """

    family = "valleyrat"
    yara_rules = ("valleyrat",)

    c2_addr_1 = ""
    c2_addr_2 = ""
    c2_addr_3 = ""
    c2_port_1 = ""
    c2_port_2 = ""
    c2_port_3 = ""
    protocol_1 = ""
    protocol_2 = ""
    protocol_3 = ""
    dormant_time_minute = ""
    c2_interval_minute = ""
    version = ""


    @Extractor.extractor("c2_config_1")
    def valleyrat_campaign(self, p, addr):
        try:
            self.version = p.readv_until(addr, b":\x00b\x00b\x00|\x00").decode("utf16")[::-1].split("|")[0]

        except Exception as error:
            log.warning(error)

    @Extractor.extractor("c2_config_2")
    def valleyrat_c2(self, p, addr):
        try:
            self.c2_addr_1 = p.readv_until(addr, b":\x001\x00p\x00|\x00").decode("utf16")[::-1].split("|")[0]
            self.c2_port_1 = p.readv_until(addr, b":\x001\x00o\x00|\x00").decode("utf16")[::-1].split("|")[0]
            protocol_id_1 = int(p.readv_until(addr, b":\x001\x00t\x00|\x00").decode("utf16")[::-1].split("|")[0])
            if protocol_id_1 == 1:
                self.protocol_1 = "TCP"
            elif protocol_id_1 == 0:
                self.protocol_1 = "UDP"
            else:
                self.protocol_1 = "UNKOWN"

            self.c2_addr_2 = p.readv_until(addr, b":\x002\x00p\x00|\x00").decode("utf16")[::-1].split("|")[0]
            self.c2_port_2 = p.readv_until(addr, b":\x002\x00o\x00|\x00").decode("utf16")[::-1].split("|")[0]
            protocol_id_2 = int(p.readv_until(addr, b":\x001\x00t\x00|\x00").decode("utf16")[::-1].split("|")[0])
            if protocol_id_2 == 1:
                self.protocol_2 = "TCP"
            elif protocol_id_2 == 0:
                self.protocol_2 = "UDP"
            else:
                self.protocol_2 = "UNKOWN"

            self.c2_addr_3 = p.readv_until(addr, b":\x003\x00p\x00|\x00").decode("utf16")[::-1].split("|")[0]
            self.c2_port_3 = p.readv_until(addr, b":\x003\x00o\x00|\x00").decode("utf16")[::-1].split("|")[0]
            protocol_id_3 = int(p.readv_until(addr, b":\x001\x00t\x00|\x00").decode("utf16")[::-1].split("|")[0])
            if protocol_id_3 == 1:
                self.protocol_3 = "TCP"
            elif protocol_id_3 == 0:
                self.protocol_3 = "UDP"
            else:
                self.protocol_3 = "UNKOWN"

            self.dormant_time_minute = p.readv_until(addr, b":\x00l\x00c\x00|\x00").decode("utf16")[::-1].split("|")[0]
            self.c2_interval_minute = p.readv_until(addr, b":\x00d\x00d\x00|\x00").decode("utf16")[::-1].split("|")[0]

        except Exception as error:
            log.warning(error)
      

    @Extractor.final
    def valleyrat(self, p):
        try:
            config = {
                    "family": self.family,
                    "c2_addr_1": self.c2_addr_1,
                    "c2_port_1": self.c2_port_1,
                    "c2_protocol_1": self.protocol_1,
                    "c2_addr_2": self.c2_addr_2, 
                    "c2_port_2": self.c2_port_2,
                    "c2_protocol_2": self.protocol_2,
                    "c2_addr_3": self.c2_addr_3, 
                    "c2_port_3": self.c2_port_3,
                    "c2_protocol_3": self.protocol_3,
                    "dormant_time_minute": self.dormant_time_minute,
                    "c2_interval_minute":self.c2_interval_minute,
                    "version": self.version,
            }
            return config
        except Exception as error:
            log.warning(error)
            return None

