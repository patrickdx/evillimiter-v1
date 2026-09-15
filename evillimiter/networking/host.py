from evillimiter.console.io import IO


class Host(object):
    def __init__(self, ip, mac, name):
        self.ip = ip
        self.mac = mac
        self.name = name
        self.spoofed = False
        self.limited = False
        self.blocked = False
        self.watched = False

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        # Keep every view (hosts, monitor, analyze, reconnects) nonblank,
        # including hosts whose lookup returned only whitespace or None.
        self._name = (str(value).strip() if value is not None else '') or 'Unknown device'

    def __eq__(self, other):
        return self.ip == other.ip

    def __hash__(self):
        return hash((self.mac, self.ip))

    def pretty_status(self):
        if self.limited:
            return '{}Limited{}'.format(IO.Fore.LIGHTRED_EX, IO.Style.RESET_ALL)
        elif self.blocked:
            return '{}Blocked{}'.format(IO.Fore.RED, IO.Style.RESET_ALL)
        else:
            return 'Free'
