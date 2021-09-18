# -*-coding:utf-8-*-
import itertools
list1=""
c=0
a=""
s="AXAXDFDXXAFADFGFXAADFGDXGFDXFFDFAXDXFFFFXGXGAAXAGAFDDXFFDXFFDXDXDXDXGFDFAXFXAADXAAGAXGDGXAXAFAXXFFXADFFGAADXDXAXDFDFDXXAXXDXDAAAAAFAXAAAFGGAFGFGXADXXADFGADXDFDFGAGFDGAXFGAXDGDADXFFFFDAGFADXGDX"
list=list(itertools.permutations(['a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z'],25))
for j in list:
    list1=j
    for i in range(0,len(s),2):
        if s[i]=='A':
            c+=0
        else:
            if s[i]=='D':
                c+=5
            else:
                if s[i]=='F':
                    c+=10
                else:
                    if s[i]=='G':
                        c+=15
                    else:
                        if s[i]=='X':
                            c+=20
        if s[i+1]=='A':
            c+=0
        else:
            if s[i+1]=='D':
                c+=1
            else:
                if s[i+1]=='F':
                    c+=2
                else:
                    if s[i+1]=='G':
                        c+=3
                    else:
                        if s[i+1]=='X':
                            c+=4
        a+=list1[c]
        c=0
    print(a)
    a=""

