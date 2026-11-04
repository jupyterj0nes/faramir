"""Writes the clean reference built into faramir: what stock hosts carry.

    python scripts/measure_clean.py <faramir csv>[|<exclude regex>] ...

Each CSV is a faramir timeline of a clean host (nothing planted). Every
distinct (event_type, detail) pair goes into src/hunt/clean/windows.csv or
src/hunt/clean/linux.csv by the event_type's prefix; rows whose detail,
location or user match the exclude regex (the collection's own activity, the
lab's beacon) are left out. The binary normalises the pairs at start-up with
the same identity function as the rows it judges (user names, SIDs, GUIDs,
drive letters and version folders neutralised), so a value seen on a clean
host is `habitual` on every host whatever its rules say.

Re-run it whenever the techniques change what they write in `detail`, and
run faramir on the reference evidence again first.
"""
import csv
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', 'src', 'hunt', 'clean')


def main():
    seen = {'windows': {}, 'linux': {}}
    sources = {'windows': [], 'linux': []}
    for arg in sys.argv[1:]:
        path, excl = arg.split('|', 1) if '|' in arg else (arg, '')
        exclude = re.compile(excl, re.I) if excl else None
        counts = {'windows': 0, 'linux': 0}
        with open(path, encoding='utf-8', newline='') as f:
            for r in csv.DictReader(f):
                et = r.get('event_type') or r.get('artifact') or ''
                detail = r.get('detail') or r.get('commandline') or ''
                os_ = 'windows' if et.startswith('windows:') else 'linux' if et.startswith('linux:') else None
                if os_ is None or not detail.strip():
                    continue
                probe = ' '.join([detail, r.get('log_filename', ''), r.get('target_user_name', ''), r.get('dst_computer', '')])
                if exclude and exclude.search(probe):
                    continue
                key = (et, detail)
                if key not in seen[os_]:
                    seen[os_][key] = True
                    counts[os_] += 1
        for os_, n in counts.items():
            if n:
                sources[os_].append(f'{os.path.basename(path)} ({n} new)')
        print(f'{path}: windows {counts["windows"]}, linux {counts["linux"]} new pairs')
    os.makedirs(OUT, exist_ok=True)
    for os_ in ('windows', 'linux'):
        out = os.path.join(OUT, f'{os_}.csv')
        with open(out, 'w', encoding='utf-8', newline='') as f:
            w = csv.writer(f, lineterminator='\n')
            w.writerow(['event_type', 'detail'])
            for et, detail in sorted(seen[os_]):
                w.writerow([et, detail])
        print(f'wrote {out}: {len(seen[os_])} pairs from {", ".join(sources[os_]) or "nothing"}')


if __name__ == '__main__':
    main()
