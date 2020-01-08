### 실습 풀이
```yara
rule  helloyara
{
  strings:
    $str="HELLO YARA"
  condition:
    $str
}
```
```yara
rule  helloyara
{
  strings:
    $yara="yara" nocase
    $o="o" nocase
  condition:
    #yara==1 and #o==0
}
```
```yara
rule  helloyara
{
  strings:
    $hello="hello" nocase
    $a="a"
  condition:
    $a>=4 and $hello
}
```

### 정답
```yara
rule  helloyara
{
  strings:
    $str="HELLO"
  condition:
    $str
}
```
```yara
rule  helloyara
{
  strings:
    $hi="Hi"
    $hell="hell"
    $yara="YARA"
  condition:
    $hi or ($hell and $yara)
}
```
```yara
rule  helloyara
{
  strings:
    $ra="ra" nocase
    $o="o"
  condition:
    #ra>3 or #o>4
}
```
