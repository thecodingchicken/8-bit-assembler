; product = 0
; loop until x is 0:
;    load x
;    subtract 1
;    store x
;
;    load product
;    add y
;    store product
; output product
lda 14 ; x
sub 12 ; set ram [12] to 1 externally before executing
jc 6
lda 13 ; load product
out
hlt
sta 14 ; store x
lda 13 ; load product
add 15 ; add y to product
sta 13 ; store product
jmp 0