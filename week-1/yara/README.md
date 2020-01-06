### yara
  - yara64.exe test.yara sample.txt // cmd 이용
  - test.yara // 생성
  - sample.txt // 생성
  
### test.yara
```yara
rule Test
{
    strings:
      $a ="hello"
      $b ="world"

    condition:
        any of them
}
```
  - all of them // all
  - any of them // or
