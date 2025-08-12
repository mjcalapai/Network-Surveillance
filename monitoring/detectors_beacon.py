from collections import defaultdict
import statistics as stats

def find_beacons(records, min_contacts=6, max_interval=120, jitter_ratio=0.15):
    by_pair = defaultdict(list)
    for r in records:
        by_pair[(r["src_ip"], r["dst_ip"])].append(r["timestamp"])
    alerts=[]
    for (src,dst), tlist in by_pair.items():
        if len(tlist) < min_contacts: continue
        tlist.sort()
        deltas = [tlist[i+1]-tlist[i] for i in range(len(tlist)-1)]
        if not deltas: continue
        avg = sum(deltas)/len(deltas)
        if avg <= max_interval:
            sd = stats.pstdev(deltas)
            if sd/avg <= jitter_ratio:  # fairly regular
                alerts.append({
                  "type":"possible_beaconing",
                  "src_ip":src,"dst_ip":dst,
                  "contacts":len(tlist),"avg_interval_s":round(avg,1),
                  "jitter":round(sd/avg,3),"first_seen":tlist[0],"last_seen":tlist[-1],
                  "severity":"medium"
                })
    return alerts