### 정규식 실습 풀이
.*[0-z]@naver\.com

010.[0-9]{4}.[0-9]{4} // 문제 조건 추가 -_. 으로 전화번호 구분 (010.1234.5678, 010_9999_9999)추가

추가 문제 
1. ppt확장자 매칭(ppt, pptx) : .+ppt$|.+pptx$
2. docx확장자 매칭(doc, docx) : .+doc$|.+docx$
- abcd.docx
- docx.pptx
- docx.doc
- test.ppt
- pptx.ppt
- .abcd.pptx.docx
- .docx.docx.docx
- .aab.ccd.pptx.ppt

```yara
rule regex
{
  strings:
    $http=/http/
    $yara=/yara/
  conditin:
    $http and $yara
}
```

```yara
rule regex
{
  strings:
    $http=/http/
    $naver=/naver/
  conditin:
    $http and $naver
}
```

```yara
rule regex
{
  strings:
    $http=/http/
    $google=/google/
  conditin:
    $http and $google
}
```
### 정답
.+@naver\.com

010[-_\.][0-9]{4}[-_\.][0-9]{4}

1. ppt확장자 매칭(ppt, pptx) : .*\.pptx?$
2. docx확장자 매칭(doc, docx) : .*\.docx?$
