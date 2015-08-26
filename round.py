print("package argon2")
print()
print("func block(z, a, b *[128]uint64) {")

def G(a, b, c, d):
    print("\t%s = %s + %s" % (a, a, b))
    print("\t%s = %s ^ %s" % (d, d, a))
    print("\t%s = %s>>32 | %s<<32" % (d, d, d))
    print("\t%s = %s + %s" % (c, c, d))
    print("\t%s = %s ^ %s" % (b, b, c))
    print("\t%s = %s>>24 | %s<<40" % (b, b, b))
    print("\t%s = %s + %s" % (a, a, b))
    print("\t%s = %s ^ %s" % (d, d, a))
    print("\t%s = %s>>16 | %s<<48" % (d, d, d))
    print("\t%s = %s + %s" % (c, c, d))
    print("\t%s = %s ^ %s" % (b, b, c))
    print("\t%s = %s>>63 | %s<<1" % (b, b, b))

def P():
    G("v0", "v4", "v8", "v12")
    G("v1", "v5", "v9", "v13")
    G("v2", "v6", "v10", "v14")
    G("v3", "v7", "v11", "v15")
    G("v0", "v5", "v10", "v15")
    G("v1", "v6", "v11", "v12")
    G("v2", "v7", "v8", "v13")
    G("v3", "v4", "v9", "v14")

for i in range(16):
    print("\tvar v%d uint64" % i)
print()

for b in range(0, 128, 16):
    for i, j in zip(range(16), range(b, b+16)):
        print("\tv%d = a[%d] ^ b[%d]" % (i, j, j))
    P()
    for i, j in zip(range(16), range(b, b+16)):
        print("\tz[%d] = v%d" % (j, i))
    print()

for b in range(0, 16, 2):
    for i, j in zip(range(0, 16, 2), range(b, 128, 16)):
        print("\tv%d = z[%d]" % (i, j))
        print("\tv%d = z[%d]" % (i+1, j+1))
    P()
    for i, j in zip(range(0, 16, 2), range(b, 128, 16)):
        print("\tz[%d] = v%d" % (j, i))
        print("\tz[%d] = v%d" % (j+1, i+1))
    print()

for i in range(128):
    print("\tz[%d] ^= a[%d] ^ b[%d]" % (i, i, i))

print("}")
