### 실습 풀이
```yara
rule at
{
  strings:
    $exe=/MZ/
  condition:
    $exe
}
```
```yara
rule at
{
  strings:
    $png=/PNG/
  condition:
    $png
}
```
```yara
rule at
{
  strings:
    $yara="YARA"
  condition:
    $yara at 5
}
```
```yara
rule at
{
  strings:
    $jpeg={FF D8 FF E0}
  condition:
    $hpeg at 0
}
```
### 정답
```yara
rule at
{
  strings:
    $exe=/MZ/
  condition:
    $exe
}
```
```yara
rule at
{
  strings:
    $png={89 50 4E 47 0D 0A 1A 0A}
  condition:
    $png at 0
}
```
```yara
rule at
{
  strings:
    $yara="YARA"
  condition:
    $yara at 5
}
```
```yara
rule at
{
  strings:
    $jpeg={FF D8 FF E0}
  condition:
    $jpeg at 0
}
```
