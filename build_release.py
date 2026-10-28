#!/usr/bin/env python3
"""Build source archives from an explicit allowlist, never from the workspace root."""
import gzip
import hashlib
import io
from pathlib import Path
import tarfile
import zipfile

ROOT=Path(__file__).resolve().parent
VERSION='1.1.0'
NAME='tblockerbridge-'+VERSION

def files():
    names=['README.md','LICENSE','SECURITY.md','CHANGELOG.md','.gitignore','.gitattributes',
           'install.sh','scripts-bootstrap.sh','installer.py','build_release.py']
    for pattern in ['src/*.py','tests/test_*.py','docs/*.md','.github/workflows/*.yml']:
        names.extend(str(path.relative_to(ROOT)).replace('\\','/') for path in ROOT.glob(pattern))
    return sorted(set(names))

def main():
    target=ROOT/'dist';target.mkdir(exist_ok=True)
    executable={'install.sh','scripts-bootstrap.sh','installer.py','build_release.py'}
    archive=io.BytesIO()
    with tarfile.open(fileobj=archive,mode='w',format=tarfile.PAX_FORMAT) as tar:
        with zipfile.ZipFile(target/(NAME+'.zip'),'w',compression=zipfile.ZIP_DEFLATED) as zipout:
            for name in files():
                data=(ROOT/name).read_bytes().replace(b'\r\n',b'\n')
                mode=0o755 if name in executable else 0o644
                item=tarfile.TarInfo(NAME+'/'+name);item.size=len(data);item.mode=mode;item.mtime=0
                tar.addfile(item,io.BytesIO(data))
                zitem=zipfile.ZipInfo(NAME+'/'+name);zitem.external_attr=(0o100000|mode)<<16
                zitem.compress_type=zipfile.ZIP_DEFLATED;zipout.writestr(zitem,data)
    with (target/(NAME+'.tar.gz')).open('wb') as output:
        with gzip.GzipFile(filename='',mode='wb',fileobj=output,mtime=0) as packed:packed.write(archive.getvalue())
    hashes=[]
    for suffix in ['.tar.gz','.zip']:
        path=target/(NAME+suffix);hashes.append(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+path.name)
    (target/'SHA256SUMS').write_text('\n'.join(hashes)+'\n',encoding='utf8')
    print('\n'.join(hashes))

if __name__=='__main__':main()
