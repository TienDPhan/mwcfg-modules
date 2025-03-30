rule valleyrat {
    meta:
        author      = "Tien D. Phan"
        description = "ValleyRAT Configuration Extractor"
        hash        = "dc50d25364dec52785a70a0d9ebbf59aef44c69bbd6b0d7c00d032abcca3df76"
        created     = "2025-03-30"
        os          = "windows"
        tlp         = "white"
        rev         = 1
    strings:
        $c2_config_1 = /\|\x00.{1,100}:\x00d\x00b\x00\|\x00.{1,100}:\x00l\x00k\x00\|\x00.{1,100}:\x00h\x00s\x00\|\x00.{1,100}:\x00l\x00d\x00\|\x00.{1,100}:\x00l\x00l\x00\|\x00.{1,100}:\x00h\x00b\x00\|\x00.{1,100}:\x00p\x00j\x00\|\x00.{1,100}:\x00z\x00b\x00\|\x00.{1,100}:\x00b\x00b\x00\|\x00/

        $c2_config_2 = /:\x00z\x00f\x00\|\x00.{1,100}:\x00l\x00c\x00\|\x00.{1,100}:\x00d\x00d\x00\|\x00.{1,100}:\x003\x00t\x00\|\x00.{1,100}:\x003\x00o\x00\|\x00.{1,100}:\x003\x00p\x00\|\x00.{1,100}:\x002\x00t\x00\|\x00.{1,100}:\x002\x00o\x00\|\x00.{1,100}:\x002\x00p\x00\|\x00.{1,100}:\x001\x00t\x00\|\x00.{1,100}:\x001\x00o\x00\|\x00.{1,100}:\x001\x00p\x00\|\x00/
   condition:
        uint16(0) == 0x5A4D and
        all of them
}