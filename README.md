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

