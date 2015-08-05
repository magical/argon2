
for b in range(0, 128, 16):
    print("\t%s = _P(%s)" % (
        ", ".join("z[%d]" % i for i in range(b, b+16)),
        ", ".join("a[%d]^b[%d]" % (i, i) for i in range(b, b+16))))

for b in range(0, 16, 2):
    print("\t%s = _P(%s)" % (
        ", ".join("z[%d], z[%d]" % (i, i+1) for i in range(b, 128, 16)),
        ", ".join("z[%d], z[%d]" % (i, i+1) for i in range(b, 128, 16))))
