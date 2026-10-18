import argparse
import heapq
import random

VERBOSE = False

SCENARIOS = [
    ("A: Reliable channel", 0.0, 0.0, 0.0),
    ("B: Packet loss 0.10", 0.10, 0.0, 0.0),
    ("C: Mixed errors", 0.05, 0.05, 0.10),
]


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


class Pkt:
    def __init__(self, kind, seq, payload, csum=None):
        self.kind = kind
        self.seq = seq
        self.payload = payload
        body = kind.encode() + seq.to_bytes(4, "big") + payload
        self.csum = checksum(body) if csum is None else csum

    def ok(self):
        body = self.kind.encode() + self.seq.to_bytes(4, "big") + self.payload
        return checksum(body) == self.csum

    def corrupted(self):
        b = bytearray(self.payload)
        b[random.randrange(len(b))] ^= 1 << random.randrange(8)
        return Pkt(self.kind, self.seq, bytes(b), self.csum)


class GBN:
    def __init__(self, a):
        self.a = a
        self.P = a.packets
        self.N = a.window
        self.M = 2 ** a.k
        self.tx_time = a.size * 8 / a.rate * 1000.0
        self.prop = a.rtt / 2.0
        self.now = 0.0
        self.heap = []
        self.cnt = 0
        self.link_free = 0.0
        self.payloads = [f"EOC-MSG-{i:05d}".encode() for i in range(self.P)]
        self.base = 0
        self.nextseq = 0
        self.tok = 0
        self.expectedseqnum = 0
        self.delivered = []
        self.st = dict(sent=0, retx=0, lost=0, corrupt=0, delayed=0, timeouts=0)

    def push(self, t, kind, data):
        heapq.heappush(self.heap, (t, self.cnt, kind, data))
        self.cnt += 1

    def log(self, msg):
        if VERBOSE:
            print(f"[{self.now:10.3f} ms] {msg}")

    def channel(self, pkt, dest, depart, label):
        a = self.a
        if random.random() < a.loss:
            self.st["lost"] += 1
            self.log(f"LOSS      {label} lost in channel")
            return
        if random.random() < a.corrupt:
            pkt = pkt.corrupted()
            self.st["corrupt"] += 1
            self.log(f"CORRUPT   {label} corrupted in channel")
        d = self.prop
        if random.random() < a.delay:
            extra = random.uniform(0, a.delay_max)
            d += extra
            self.st["delayed"] += 1
            self.log(f"DELAY     {label} delayed by extra {extra:.1f} ms")
        self.push(depart + d, dest, pkt)

    def transmit(self, i, retx=False):
        seq = i % self.M
        pkt = Pkt("D", seq, self.payloads[i])
        start = max(self.now, self.link_free)
        depart = start + self.tx_time
        self.link_free = depart
        self.st["sent"] += 1
        if retx:
            self.st["retx"] += 1
        tag = "RESEND" if retx else "SEND"
        self.log(f"{tag:<9} DATA seq={seq} (pkt#{i}) base={self.base} nextseqnum={self.nextseq}")
        self.channel(pkt, "rx", depart, f"DATA seq={seq}")
        return depart

    def send_ack(self, seq):
        pkt = Pkt("A", seq, b"ACK")
        self.log(f"ACK       receiver sends cumulative ACK seq={seq}")
        self.channel(pkt, "tx", self.now, f"ACK seq={seq}")

    def start_timer(self, t):
        self.tok += 1
        self.push(t + self.a.timeout, "timeout", self.tok)

    def stop_timer(self):
        self.tok += 1

    def send_new(self):
        while self.nextseq < self.base + self.N and self.nextseq < self.P:
            depart = self.transmit(self.nextseq)
            if self.base == self.nextseq:
                self.start_timer(depart)
            self.nextseq += 1

    def on_timeout(self, tok):
        if tok != self.tok or self.base >= self.nextseq:
            return
        self.st["timeouts"] += 1
        self.log(f"TIMEOUT   timer expired, base={self.base} nextseqnum={self.nextseq}, resending all outstanding packets")
        first = None
        for i in range(self.base, self.nextseq):
            d = self.transmit(i, True)
            if first is None:
                first = d
        self.start_timer(first)

    def on_ack(self, p):
        if not p.ok():
            self.log("RECEIVE   sender got corrupted ACK, discarded")
            return
        self.log(f"RECEIVE   sender got ACK seq={p.seq} base={self.base} nextseqnum={self.nextseq}")
        for i in range(self.base, self.nextseq):
            if i % self.M == p.seq:
                self.base = i + 1
                if self.base == self.nextseq:
                    self.stop_timer()
                else:
                    self.start_timer(self.now)
                self.log(f"WINDOW    cumulative ACK, base={self.base} nextseqnum={self.nextseq}")
                self.send_new()
                return
        self.log("RECEIVE   duplicate/old ACK ignored")

    def on_data(self, p):
        if not p.ok():
            self.log(f"RECEIVE   receiver got corrupted packet, discarded (expectedseqnum={self.expectedseqnum % self.M})")
            if self.expectedseqnum > 0:
                self.send_ack((self.expectedseqnum - 1) % self.M)
            return
        if p.seq == self.expectedseqnum % self.M:
            self.log(f"RECEIVE   receiver got DATA seq={p.seq} in order, delivered (expectedseqnum={self.expectedseqnum % self.M})")
            self.delivered.append(p.payload)
            self.send_ack(p.seq)
            self.expectedseqnum += 1
        else:
            self.log(f"RECEIVE   receiver got DATA seq={p.seq} out of order, discarded (expectedseqnum={self.expectedseqnum % self.M})")
            if self.expectedseqnum > 0:
                self.send_ack((self.expectedseqnum - 1) % self.M)

    def run(self):
        self.send_new()
        while self.heap and self.base < self.P and self.now < self.a.max_time:
            t, _, kind, data = heapq.heappop(self.heap)
            self.now = t
            if kind == "timeout":
                self.on_timeout(data)
            elif kind == "rx":
                self.on_data(data)
            else:
                self.on_ack(data)
        self.summary()

    def summary(self):
        correct = self.delivered == self.payloads
        print("\n===== SUMMARY =====")
        print("protocol            : GBN")
        print(f"packets             : {self.P}")
        print(f"window N            : {self.N}")
        print(f"seq bits k          : {self.a.k} (modulo {self.M})")
        print(f"seed                : {self.a.seed}")
        print(f"transmission time   : {self.tx_time:.3f} ms per packet")
        print(f"completion time     : {self.now:.3f} ms")
        print(f"packets sent        : {self.st['sent']}")
        print(f"retransmissions     : {self.st['retx']}")
        print(f"timeouts            : {self.st['timeouts']}")
        print(f"lost in channel     : {self.st['lost']}")
        print(f"corrupted in channel: {self.st['corrupt']}")
        print(f"delayed in channel  : {self.st['delayed']}")
        print(f"delivered           : {len(self.delivered)}/{self.P}")
        print(f"all correct/in order: {correct}")
        if self.now > 0:
            print(f"goodput             : {len(self.delivered) * self.a.size * 8 / (self.now / 1000.0) / 1e6:.4f} Mbps")


def main():
    for name, loss, corrupt, delay in SCENARIOS:
        a = argparse.Namespace(packets=200, window=4, k=3, loss=loss, corrupt=corrupt, delay=delay,
                               delay_max=200.0, timeout=1000.0, seed=1044, rate=2e6, rtt=500.0,
                               size=1000, max_time=1e8)
        print("\n########## Scenario " + name + " ##########")
        random.seed(a.seed)
        GBN(a).run()


if __name__ == "__main__":
    main()
