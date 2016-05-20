__author__ = 'spydir'


files = [
         {"name":"Registry","path":"/Windows/System32/config/SAM"},
         {"name":"Registry","path":"/Windows/System32/config/security"},
         {"name":"Registry","path":"/Windows/System32/config/software"},
         {"name":"Registry","path":"/Windows/System32/config/SYSTEM"},
         {"name":"Evt","path":"/Windows/System32/config/AppEvent.evt"},
         {"name":"Evt","path":"/Windows/System32/config/SecEvent.evt"},
         {"name":"Evt","path":"/Windows/System32/config/SysEvent.evt"},
         {"name":"MFT","path":"/$MFT"}
        ]


directories = [
                {'name':"evtx",'path':"/Windows/System32/Winevt/logs"},
                {'name':"config",'path':"/Windows/System32/config"}
              ]