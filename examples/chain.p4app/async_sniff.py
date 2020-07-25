from select import select
from scapy.all import conf, ETH_P_ALL, MTU, plist

# Stop sniff() asynchronously
# Source: https://github.com/secdev/scapy/issues/989#issuecomment-380044430

def sniff(store=False, prn=None, lfilter=None,
          stop_event=None, refresh=.1, *args, **kwargs):
    """Sniff packets
sniff([count=0,] [prn=None,] [store=1,] [offline=None,] [lfilter=None,] + L2ListenSocket args)

  store: wether to store sniffed packets or discard them
    prn: function to apply to each packet. If something is returned,
         it is displayed. Ex:
         ex: prn = lambda x: x.summary()
lfilter: python function applied to each packet to determine
         if further action may be done
         ex: lfilter = lambda x: x.haslayer(Padding)
stop_event: Event that stops the function when set
refresh: check stop_event.set() every refresh seconds
    """
    s = conf.L2listen(type=ETH_P_ALL, *args, **kwargs)
    lst = []
    try:
        while True:
            if stop_event and stop_event.is_set():
                break
            sel = select([s], [], [], refresh)
            if s in sel[0]:
                p = s.recv(MTU)
                if p is None:
                    break
                if lfilter and not lfilter(p):
                    continue
                if store:
                    lst.append(p)
                if prn:
                    r = prn(p)
                    if r is not None:
                        print(r)
    except KeyboardInterrupt:
        pass
    finally:
        s.close()

    return plist.PacketList(lst, "Sniffed")
