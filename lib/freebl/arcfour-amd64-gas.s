# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# none of the functions are used as a target of an indirect call, so
# it's safe to set IBT. If we ever need to put these at the end of a
# function table pointer, then we should and ENDBR64 instructions as the
# first instruction of each function. */
# reference names are in /usr/include/elf.h
        .section        .note.gnu.property,"a"
        .align 8
        .long    1f - 0f # note_gnu_name_end - note_gnu_name
        .long    4f - 1f # note_gnu_descriptor_end -note_gnu_descriptor
        .long    5 # GNU_PROPERTY_TYPE_0
0: #note_gnu_name
        .string  "GNU"
1: #note_gnu_end
   #note_gnu_descriptor
        .align 8
        .long    0xc0000002 # GNU_PROPERTY_X86_FEATURE_1_AND
        .long    3f - 2f #note_gnu_flags_end - note_gnu_flags
2: #note_gnu_flags
        .long    0x3    # GNU_PROPERTY_X86_FEATURE_1_IBT = 1 |
                        # GNU_PROPERTY_X86_FEATURE_1_SHSTK = 2
3: #note_gnu_flags_end
        .align 8
4: #note_gnu_descriptor_end

# ** ARCFOUR implementation optimized for AMD64.
# **
# ** The throughput achieved by this code is about 320 MBytes/sec, on
# ** a 1.8 GHz AMD Opteron (rev C0) processor.

.text
.align 16
.globl ARCFOUR
.type ARCFOUR,@function
ARCFOUR:
	pushq	%rbp
	pushq	%rbx
	movq	%rdi,		%rbp	# key = ARG(key)
	movq	%rsi,		%rbx	# rbx = ARG(len)
	movq	%rdx,		%rsi	# in = ARG(in)
	movq	%rcx,		%rdi	# out = ARG(out)
	movq	(%rbp),		%rcx	# x = key->x
	movq	8(%rbp),	%rdx	# y = key->y
	addq	$16,		%rbp	# d = key->data
	incq	%rcx			# x++
	andq	$255,		%rcx	# x &= 0xff
	leaq	-8(%rbx,%rsi),	%rbx	# rbx = in+len-8
	movq	%rbx,		%r9	# tmp = in+len-8
	movq	0(%rbp,%rcx,8),	%rax	# tx = d[x]
	cmpq	%rsi,		%rbx	# cmp in with in+len-8
	jl	.Lend			# jump if (in+len-8 < in)

.Lstart:
	addq	$8,		%rsi		# increment in
	addq	$8,		%rdi		# increment out

	# generate the next 8 bytes of the rc4 stream into %r8
	movq	$8,		%r11		# byte counter
1:	addb	%al,		%dl		# y += tx
	movl	0(%rbp,%rdx,8),	%ebx		# ty = d[y]
	movl	%ebx,		0(%rbp,%rcx,8)	# d[x] = ty
	addb	%al,		%bl		# val = ty + tx
	movl	%eax,		0(%rbp,%rdx,8)	# d[y] = tx
	incb	%cl				# x++		(NEXT ROUND)
	movl	0(%rbp,%rcx,8),	%eax		# tx = d[x]	(NEXT ROUND)
	movb	0(%rbp,%rbx,8),	%r8b		# val = d[val]
	decb	%r11b
	rorq	$8,		%r8		# (ror does not change ZF)
	jnz 	1b

	# xor 8 bytes
	xorq	-8(%rsi),	%r8
	cmpq	%r9,		%rsi		# cmp in+len-8 with in
	movq	%r8,		-8(%rdi)
	jle	.Lstart				# jump if (in <= in+len-8)

.Lend:
	addq	$8,		%r9		# tmp = in+len

	# handle the last bytes, one by one
1:	cmpq	%rsi,		%r9		# cmp in with in+len
	jle	.Lfinished			# jump if (in+len <= in)
	addb	%al,		%dl		# y += tx
	movl	0(%rbp,%rdx,8),	%ebx		# ty = d[y]
	movl	%ebx,		0(%rbp,%rcx,8)	# d[x] = ty
	addb	%al,		%bl		# val = ty + tx
	movl	%eax,		0(%rbp,%rdx,8)	# d[y] = tx
	incb	%cl				# x++		(NEXT ROUND)
	movl	0(%rbp,%rcx,8),	%eax		# tx = d[x]	(NEXT ROUND)
	movb	0(%rbp,%rbx,8),	%r8b		# val = d[val]
	xorb	(%rsi),		%r8b		# xor 1 byte
	movb	%r8b,		(%rdi)
	incq	%rsi				# in++
	incq	%rdi				# out++
	jmp 1b

.Lfinished:
	decq	%rcx				# x--
	movb	%dl,		-8(%rbp)	# key->y = y
	movb	%cl,		-16(%rbp)	# key->x = x
	popq	%rbx
	popq	%rbp
	ret
.L_ARCFOUR_end:
.size ARCFOUR,.L_ARCFOUR_end-ARCFOUR

# Magic indicating no need for an executable stack
.section .note.GNU-stack,"",@progbits
.previous
