### 추가 ppt 60p ~ end
```yara
rlue of
{
  strings:
    $str1="test1"
    $str2="test2"
    $str3="test3"
  condition:
    2 of ($str1, str2, $str3)
}
```
  - of를 이용하여 선택한 문자열 중에서 일치하는 문자열의 최소 개수를 설정할 수 있다.
  - of 앞에 적어도 몇 개의 문자열이 일치하기를 원하는지 적고, of 뒤에 문자열들을 적어서 사용
```yara
  condition:
    2 of ($str*)
```
  - * 이라는 Wild card를 사용하여 식별자들을 선택할 수 있습니다.
  - Wild card인 * 뒤에는 아무 값이나 와도 상관 없다는 뜻
```yara
rlue of them
{
  strings:
    $str1="test1"
    $str2="test2"
    $str3="test3"
  condition:
    2 of them
}
```
  - 위에 사용한 Wild card인 *을 응용하면 $*는 모든 식별자를 의미
  - $*가 아닌 them을 이용하여도 모든 식별자를 가리킬 수 있으며, of와 같이 쓰일 경우 () 없이 사용가능
  - all of them // 모든 식별자가 존재해야 참(true)
  - any of them // 명시한 식별자 중에서 적어도 한 개 이상 존재할 경우 참(true)
```yara
rule exe:EXE
{
  strings:
    $mz="MZ"
  condition:
    $mz at 0
}

rule rul:URL
{
  strings:
    $url=/(https{0,1}:\/\/){0,1}.*\.naver.com/
  condition:
    exe and $url
}
```
  - yara.exe -r -t EXE rules.yara probs1 // 테그로 EXE를 만족하는 값 출력
  - yara.exe -r -t URL rules.yara probs1 // 테그로 URL을 만족하는 값 출력 -t 대신 -i 사용가능
