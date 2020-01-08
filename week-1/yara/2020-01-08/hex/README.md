### 실습 풀이
```yara
rule hex
{
  strings:
    $bc={42 43}
    $num={41 42 43 21}
  condition:
    #bc==1 or $num
}
```
```yara
rule hex
{
  strings:
    $abcd={41 42 43 44}
  condition:
    #abcd>=2
}
```
```yara
rule hex
{
  strings:
    $hex={41}
    $str="is hex"
  condition:
    $str and $hex
}
```
### 정답
```yara
rule hex
{
  strings:
    $hex={42 (43|32) ?? (20|31)}
    $str="not"
  condition:
    $hex and not $str
}
```
```yara
rule hex
{
  strings:
    $hex={41 42 43 44 [4-10] 41 42 43 44}
  condition:
    #hex
}
```
```yara
rule hex
{
  strings:
    $hex={41 4? 3? 3?}
  condition:
    $hex
}
```
