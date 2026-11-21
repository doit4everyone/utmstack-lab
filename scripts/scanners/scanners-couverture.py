#!/usr/bin/env python3
"""Mesure la couverture des règles NF (et des règles locales) face aux listes de scanners Internet.

Deux modes, sans dépendance externe (Python 3.8+) :

  couverture <nf.txt> <dossier_cidr> [liste_supp.txt ...]
      Pour chaque organisation de <dossier_cidr>/*_v4.txt (dépôt OpenFilters/internet-scanners),
      nombre d'adresses, adresses couvertes par les règles, pourcentage, adresses manquantes.

  croise <nf.txt> <dossier_cidr> <sources.txt> [liste_supp.txt ...]
      Croise les adresses sources réellement vues (sources.txt : « ip événements bloqués »,
      produit par sources-30j.py) avec les listes de scanners : par organisation, adresses vues,
      événements, bloqués, puis la part non couverte par les règles.

nf.txt et les listes supplémentaires (ex. liste officielle Modat) : une adresse ou un CIDR IPv4 par ligne,
les lignes invalides sont ignorées.
"""
import glob
import ipaddress
import os
import sys
from collections import defaultdict


def lire(path):
    iv = []
    with open(path) as f:
        for ligne in f:
            ligne = ligne.strip()
            if not ligne or not ligne[0].isdigit():
                continue
            try:
                n = ipaddress.ip_network(ligne, strict=False)
            except ValueError:
                continue
            if n.version == 4:
                iv.append((int(n.network_address), int(n.broadcast_address)))
    return fusion(iv)


def fusion(iv):
    m = []
    for a, b in sorted(iv):
        if m and a <= m[-1][1] + 1:
            m[-1][1] = max(m[-1][1], b)
        else:
            m.append([a, b])
    return m


def recouvrement(A, B):
    i = j = t = 0
    while i < len(A) and j < len(B):
        a, b = max(A[i][0], B[j][0]), min(A[i][1], B[j][1])
        if a <= b:
            t += b - a + 1
        if A[i][1] < B[j][1]:
            i += 1
        else:
            j += 1
    return t


def dans(ip, iv):
    return any(a <= ip <= b for a, b in iv)


def organisations(dossier):
    orgs = {}
    for f in sorted(glob.glob(os.path.join(dossier, "*_v4.txt"))):
        iv = lire(f)
        if iv:
            orgs[os.path.basename(f)[:-7]] = iv
    return orgs


def couverture(nf, dossier, supp):
    regles = fusion(nf + [x for s in supp for x in s])
    lignes = []
    for org, iv in organisations(dossier).items():
        tot = sum(b - a + 1 for a, b in iv)
        lignes.append((org, tot, recouvrement(iv, regles)))
    lignes.sort(key=lambda r: -(r[1] - r[2]))
    T, C = sum(r[1] for r in lignes), sum(r[2] for r in lignes)
    print(f"TOTAL {T} adresses, couvertes {C} ({100 * C / T:.1f} %)")
    print(f"{'organisation':32s} {'adresses':>9s} {'couvertes':>9s} {'%':>6s} {'manquantes':>10s}")
    for org, tot, c in lignes:
        print(f"{org:32s} {tot:9d} {c:9d} {100 * c / tot:6.1f} {tot - c:10d}")


def croise(nf, dossier, sources, supp):
    regles = fusion(nf + [x for s in supp for x in s])
    orgs = organisations(dossier)
    st = defaultdict(lambda: [0] * 6)  # IP, évts, bloqués | IP non couvertes, évts, bloqués
    total = [0, 0, 0]
    hors = []
    with open(sources) as f:
        for ligne in f:
            p = ligne.split()
            if len(p) != 3:
                continue
            a = ipaddress.ip_address(p[0])
            if a.version != 4 or a.is_private or a.is_loopback or a.is_link_local:
                continue
            ev, bl, i = int(p[1]), int(p[2]), int(a)
            couvert = dans(i, regles)
            total[0] += 1; total[1] += ev; total[2] += bl
            touche = [o for o, iv in orgs.items() if dans(i, iv)]
            for o in touche:
                s = st[o]
                s[0] += 1; s[1] += ev; s[2] += bl
                if not couvert:
                    s[3] += 1; s[4] += ev; s[5] += bl
            if not touche:
                hors.append((ev, bl, p[0]))
    print(f"Adresses publiques vues : {total[0]}, événements {total[1]}, bloqués {total[2]}")
    print(f"{'organisation':28s} {'IP':>5s} {'évts':>6s} {'bloq':>5s} | {'non couv.':>9s} {'évts':>6s} {'bloq':>5s}")
    for o, s in sorted(st.items(), key=lambda x: -x[1][4]):
        print(f"{o:28s} {s[0]:5d} {s[1]:6d} {s[2]:5d} | {s[3]:9d} {s[4]:6d} {s[5]:5d}")
    print(f"Hors de toute liste : {len(hors)} adresses, {sum(h[0] for h in hors)} événements")
    for ev, bl, ip in sorted(hors, reverse=True)[:20]:
        print(f"  {ip:16s} {ev:6d} évts {bl:5d} bloqués")


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "couverture":
        couverture(lire(sys.argv[2]), sys.argv[3], [lire(x) for x in sys.argv[4:]])
    elif len(sys.argv) >= 5 and sys.argv[1] == "croise":
        croise(lire(sys.argv[2]), sys.argv[3], sys.argv[4], [lire(x) for x in sys.argv[5:]])
    else:
        sys.exit(__doc__)
