def cvss_base_calc(cvss_base):
    if cvss_base is None:
        return -1
    x = [i for i in cvss_base.split('/')]
    d = dict()
    for i in x:
        k, v = i.split(':')
        d[k] = v

    if d['AV'] == 'N':
        av = 1.0
    if d['AV'] == 'A':
        av = 0.646
    if d['AV'] == 'L':
        av = 0.395

    if d['AC'] == 'L':
        ac = 0.71
    if d['AC'] == 'M':
        ac = 0.61
    if d['AC'] == 'H':
        ac = 0.35

    if d['Au'] == 'M':
        au = 0.45
    if d['Au'] == 'S':
        au = 0.56
    if d['Au'] == 'N':
        au = 0.704

    if d['C'] == 'N':
        c = 0.0
    if d['C'] == 'P':
        c = 0.275
    if d['C'] == 'C':
        c = 0.660

    if d['I'] == 'N':
        i = 0.0
    if d['I'] == 'P':
        i = 0.275
    if d['I'] == 'C':
        i = 0.660

    if d['A'] == 'N':
        a = 0.0
    if d['A'] == 'P':
        a = 0.275
    if d['A'] == 'C':
        a = 0.660

    Impact = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a))
    xx = 0 if Impact == 0 else 1.176
    Exploitability = 20 * av * ac * au
    BaseScore = abs((0.6 * Impact + 0.4 * Exploitability - 1.5) * xx)

    return round(BaseScore, 1)
