### 정답
```yara
rule  regex
{
  strings:
    $exe = "MZ"
    $url = /(https?:\/\/)?.*\.naver.com/
  condition:
    ($exe at 0) and $url
}
