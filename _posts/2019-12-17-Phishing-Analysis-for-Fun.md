---
title: "Phishing Analysis for Fun"
date: 2019-12-17 22:06:00 +0000
categories: Fun
---

## 발단

먼지만 쌓여가던 태블릿 2개를 팔기 위해 중고나라에 들어갔다. 그런데 굉장히 싸게 파는 아이패드가 하나 있어서 관심이 갔다. 연락을 하니깐 바로 게시물을 삭제하던데 알고 보니 피싱이었다. 이왕 이렇게 된거 해커의 서버를 분석해보았다.



## 전개

중고 거래 사이트에서 원하는걸 찾다 보면 가끔씩 시세보다 싼 매력적인 매물들이 종종 올라온다. 예를 들면 시세가 43만원인 태블릿이 38만원에 올라오거나 시세가 210만원인 노트북이 190만원에 올라오는 것이다. 이럴 때는 사기를 한번쯤 의심해보는게 좋다. 급처로 물건을 파는 사람들도 있긴 하지만 다음에 해당된다면 대부분 사기이다.

- [x] 연락처가 카톡 아이디만 올라와 있다.
- [x] 직거래 장소를 안올려뒀거나 처음 들어보는 지역명이다.
- [x] 카톡 아이디로 연락했더니 위치가 중국이나 홍콩으로 뜬다. (이 경우 99.9% 피싱)
- [x] 연락을 했더니 게시물을 바로 지운다.

사기꾼은 직거래 장소를 올려두지 않거나 이상한 직거래 장소를 올려두고 카카오톡으로 연락을 유도한다. 막상 연락하면 어쩔 수 없이 택배 거래를 하자고 얘기한다. 선뜻 믿고 입금하게 되면 바로 사기를 당하겠지만 요즘에 그런 사람은 거의 없다. 그래서 이 사기꾼들은 머리를 한번 더 굴린다. 안전거래를 하자고 말이다. 그리고서는 곧바로 피싱 사이트를 제작한다.



그렇게 만들어진 사이트의 링크를 확인해보면 네이버 도메인이 아닌 것을 확인할 수 있다.



![img](/assets/img-20191217/45FECFDD-7028-4F6F-B366-6B560932E184.png)



"도메인이 naver.com으로 끝나지 않는데 네이버인줄알고 넘어가는 사람이 어디있느냐?"라고 할 수 있지만 생각보다 많은 것 같다.



링크로 타고 들어가면 HTML을 크롤링해서 만든 페이지를 확인할 수 있다.



![img](/assets/img-20191217/49108EC0-337E-4492-8E91-61D6BA8B053A.png)



여기서 네이버 페이 결제하기를 누르면 해커가 만들어둔 화면으로 넘어간다. ~~(근데 모바일로 들어가면 모바일 페이지는 안만들었는지 로딩이 안된다. 사기를 치려면 치밀해야될텐데 너무 허술하다.)~~





![img](/assets/img-20191217/8DA6683B-8A5F-4DAD-95AF-1D9DFA0B76C7.png)



당연히 "예"를 눌러준다.



![img](/assets/img-20191217/5C33657E-AE5D-46BD-AA59-97AAA7B0EB36.png)





네이버 로그인을 유도한다. 여기서 자신의 진짜 네이버 계정을 입력하면 계정 정보가 해커의 데이터베이스에 고스란히 저장된다. 그리고 그 계정은 또 다른 피싱에 이용되거나 개인정보 판매에 이용된다. 나쁜말을 적어줄까 잠시 고민했지만 후환이 두려워서 일단 의미 없는 문자열을 입력했다.

![img](/assets/img-20191217/4C8D3928-178C-4725-AE64-B11273BB66B7.jpeg)

(그리고 분석하다가 우연히 발견한건데 정의의 사도 한분께서 이미 욕을 적어주셨다.)



![img](/assets/img-20191217/F81FEC00-E4F0-482C-AB86-8BCD9AE36BEA.png)



이제 연락처와 자신의 집 주소를 입력할 차례이다. 여기서 자신의 진짜 정보를 적으면 이 정보 또한 해커의 DB에 고스란히 저장된다.



## 위기

본격적으로 분석을 시작하려고 할 때 쯤, 사기꾼한테 연락이 왔다.



![img](/assets/img-20191217/28F81F13-2D17-4BD9-BB90-1C90908FB647.png)



자꾸 재촉하길래 서버를 닫을 것 같은 느낌이 들었다. 그래서 일단 이따가 연락준다며 시간을 벌었다. 그 후 다시 분석에 돌입했다.



## 절정

이 쯤 되면 궁금증이 생긴다. "피싱을 하는 나쁜 아이들은 과연 자신의 사이트를 안전하게 만들었을까?" 

![img](/assets/img-20191217/BFD36D0D-653C-410E-B5EF-59C658040D88.png)

아니나 다를까 역시 사기꾼들은 자신들이 피싱을 해서 힘들게 모은 자산(?)을 보호할 줄 모르고 있었다.



결과부터 말하자면, 서버에는 수많은 사람들의 개인정보가 있었다. 로그는 2019년 초부터 시작되었고, 엄청난 양의 데이터가 저장되어 있었다. 이런 정보들이 SQL 인젝션에 무방비하게 노출되어 있어 개인정보의 2차 유출이 심히 우려된다.



내부에서 사용하는 데이터는 중국어가 많이 쓰여서 무슨 의미인지는 파악을 못했다. 대충 훑어보던 중 DB에 피싱을 위한 도메인 정보가 저장되어 있는 것을 확인했다.

![img](/assets/img-20191217/5178C7CD-7387-4EB0-B625-21287C67A18B.png)



확인해보니 각 호스트의 웹 구조는 전부 똑같았다. 각각의 서버가 중앙 서버의 DB와 연결된 구조였다. 약 129개의 도메인을 동시에 운영하면서 피싱을 하는 듯 하다. 대충 견적을 보니 이 일을 주업으로 하면서 사는 사람들이 조직적으로 움직이는게 아닌가 싶었다. 사기꾼 n명당 호스트를 한두개씩 나눠주고 작업을 시키는 구조라고 생각된다.



## 결말

위와 같은 피싱에 당하지 않으려면 앞으로 링크의 도메인을 확인하는게 좋다. 하지만 서비스사의 도메인이 맞더라도 해당 서비스에서 XSS 같은 취약점이 발생하면 도메인 확인만으로는 피싱 예방이 불가능하다. 그러니 왠만하면 직거래를 하거나 새제품을 사는게 좋다고 생각한다.

**P.S.** 역시 물건은 공식 셀러한테 새 제품으로 사는게 좋은 것 같다.



#### 경고

본 게시물은 공익을 목적으로 작성되었습니다. 본 게시물에서 획득한 정보를 악용하지 말아주시기 바랍니다. 또한, 본 게시물에서 파생되는 법적 책임은 악용자 본인에게 있습니다.

본 게시물에 문제가 되는 내용이 있을 경우, 해당 내용을 수정하거나 게시물을 삭제하겠습니다. (delsponn@gmail.com)