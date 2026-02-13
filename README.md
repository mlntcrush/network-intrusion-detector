<<<<<<< HEAD
# 🛡️ Network Intrusion Detection System
> 로컬 네트워크에 연결된 미인가 기기를 탐지하고 Windows 알림으로 경보를 보내는 프로그램

![Python](https://img.shields.io/badge/Python-3.7%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📌 프로젝트 소개

집이나 사무실 네트워크에 **허가되지 않은 기기가 연결되면 즉시 알림**을 보내주는 보안 모니터링 프로그램입니다.

화이트리스트에 등록된 기기(내 노트북, 스마트폰 등)는 무시하고,
처음 보는 기기가 네트워크에 연결되면 Windows 데스크톱 팝업으로 경보를 보냅니다.

---

## ✨ 주요 기능

- 🔍 **복합 네트워크 스캔** - Windows ARP 캐시 + ARP 패킷 + ICMP ping 세 가지 방법 병행
- ✅ **화이트리스트 관리** - JSON 파일로 승인된 기기 관리, 명령어로 간편하게 추가
- 🔔 **Windows 데스크톱 알림** - 미인가 기기 발견 시 즉시 팝업 알림
- 📝 **로그 기록** - 모든 탐지 이벤트를 파일에 자동 저장
- ⚙️ **유연한 설정** - config.json으로 스캔 주기, IP 범위 등 쉽게 조정

---

## 🔧 동작 원리

### 스캔 방식

미인가 기기를 빠짐없이 탐지하기 위해 세 가지 방법을 순서대로 실행하고 결과를 합산합니다.

```
1단계: Windows ARP 캐시 읽기
       └── OS가 자동으로 기록한 통신 기록을 읽음
           AP 격리·방화벽의 영향을 받지 않음

2단계: ARP 패킷 스캔
       └── 네트워크에 직접 패킷을 전송해 응답 수집
           방금 연결된 신규 기기를 즉시 탐지

3단계: ICMP ping 스캔
       └── 위 두 방법에서 놓친 기기를 ping으로 보완
           병렬 처리로 빠른 스캔

→ 세 결과를 합산해 최종 기기 목록 생성
```

### 전체 동작 흐름

```
[주기적 스캔]
      │
      ▼
 네트워크 스캔
(ARP캐시 + ARP + ICMP)
      │
      ▼
화이트리스트와 비교
      │
  ┌───┴───┐
  ▼       ▼
등록됨   미등록
(무시)  (경보!)
          │
          ▼
   CMD 경고 출력
   Windows 팝업
   로그 기록
```

---

## 🚀 설치 방법

### 1. 사전 요구사항

- **Python 3.7 이상** - [다운로드](https://www.python.org/downloads/)
- **Npcap** - Windows 네트워크 패킷 캡처 드라이버 - [다운로드](https://npcap.com/)
  - 설치 시 **"Install Npcap in WinPcap API-compatible Mode"** 반드시 체크!

### 2. 저장소 클론

```bash
git clone https://github.com/본인아이디/network-intrusion-detector.git
cd network-intrusion-detector
```

### 3. 라이브러리 설치

관리자 권한 CMD에서 실행:

```bash
pip install -r requirements.txt
```

---

## ⚙️ 설정

### config.json

```json
{
  "scan_interval": 30,
  "ip_range": "192.168.1.0/24",
  "log_file": "network_monitor.log",
  "enable_sound": false,
  "arp_timeout": 3,
  "arp_retry": 2,
  "use_icmp": true,
  "icmp_timeout": 1,
  "icmp_workers": 50
}
```

| 항목 | 기본값 | 설명 |
|------|--------|------|
| `scan_interval` | 30 | 스캔 주기 (초) |
| `ip_range` | 192.168.1.0/24 | 스캔할 IP 범위 |
| `enable_sound` | false | 알림 소리 여부 |
| `arp_timeout` | 3 | ARP 응답 대기 시간 (초) |
| `arp_retry` | 2 | ARP 재시도 횟수 |
| `use_icmp` | true | ICMP 스캔 사용 여부 |
| `icmp_timeout` | 1 | ICMP 응답 대기 시간 (초) |
| `icmp_workers` | 50 | ICMP 병렬 처리 수 |

**IP 범위 확인 방법:**

CMD에서 `ipconfig` 입력 후 IPv4 주소 확인:
- `192.168.0.xxx` → `"ip_range": "192.168.0.0/24"`
- `192.168.1.xxx` → `"ip_range": "192.168.1.0/24"`
- `10.0.0.xxx`    → `"ip_range": "10.0.0.0/24"`

---

## 💻 사용 방법

> ⚠️ **반드시 관리자 권한 CMD에서 실행하세요!**

### 추천 순서

#### 1. 현재 네트워크 기기 확인

```bash
python network_monitor.py list
```

```
현재 네트워크 기기 목록 (3개)
===========================================================================
상태       MAC 주소             IP 주소          이름
===========================================================================
⚠️  미승인  a1:b2:c3:d4:e5:f6   192.168.0.1      알 수 없음
⚠️  미승인  11:22:33:44:55:66   192.168.0.100    알 수 없음
⚠️  미승인  aa:bb:cc:dd:ee:ff   192.168.0.101    알 수 없음
===========================================================================
승인됨: 0개 | 미승인: 3개
```

#### 2. 정상 기기를 화이트리스트에 추가

```bash
python network_monitor.py add a1:b2:c3:d4:e5:f6 "공유기"
python network_monitor.py add 11:22:33:44:55:66 "내 노트북"
python network_monitor.py add aa:bb:cc:dd:ee:ff "내 휴대폰"
```

#### 3. 모니터링 시작

```bash
python network_monitor.py
```

```
🛡️  네트워크 침입 탐지 시스템 시작
======================================================================
📋 화이트리스트 : 3개 기기 등록됨
⏱️  스캔 주기    : 30초
🌐 IP 범위      : 192.168.0.0/24
======================================================================

모니터링 중... (Ctrl+C로 종료)

[14:30:00] ✓ 3개 기기 발견 / 화이트리스트: 3개 / 다음 스캔: 30초 후
```

#### 4. 미인가 기기 탐지 시

```
==================================================
⚠️  경고: 미인가 기기 탐지!
   MAC  : bb:cc:dd:ee:ff:11
   IP   : 192.168.0.105
   시간 : 2026-02-12 14:30:22
==================================================
```

Windows 화면 우측 하단에 팝업 알림도 함께 표시됩니다.

### 명령어 전체 목록

```bash
python network_monitor.py                          # 모니터링 시작
python network_monitor.py list                     # 현재 네트워크 기기 목록
python network_monitor.py add <MAC> [이름] [설명]  # 화이트리스트 추가
python network_monitor.py help                     # 도움말
```

---

## 📂 파일 구조

```
network-intrusion-detector/
├── network_monitor.py      # 메인 프로그램
├── config.json             # 설정 파일
├── whitelist.json          # 승인된 기기 목록
├── requirements.txt        # 필요 라이브러리
├── network_monitor.log     # 로그 파일 (자동 생성)
└── README.md               # 이 파일
```

---

## 🔒 보안 참고사항

- 로컬 네트워크 내 기기만 탐지합니다 (인터넷 너머 기기는 탐지 불가)
- MAC 주소는 스푸핑될 수 있으므로 완벽한 보안 솔루션은 아닙니다
- 중요한 네트워크에서는 전문적인 보안 솔루션과 함께 사용하세요
- 스마트폰의 **"개인 정보 보호 MAC"** 기능이 켜진 경우 탐지가 불안정할 수 있습니다
  - Android: 설정 → Wi-Fi → 연결된 네트워크 → MAC 주소 유형 → **기기 MAC 사용**
  - iPhone: 설정 → Wi-Fi → 연결된 네트워크 옆 **(i)** → 개인용 Wi-Fi 주소 **OFF**

---

## 🛠️ 문제 해결

| 증상 | 원인 | 해결 방법 |
|------|------|----------|
| 관리자 권한 오류 | 일반 CMD 실행 | CMD를 관리자 권한으로 재실행 |
| 기기가 0개 탐지 | IP 범위 불일치 | `ipconfig`로 IP 확인 후 config.json 수정 |
| 일부 기기만 탐지 | AP 격리 설정 | 공유기 관리 페이지에서 AP 격리 OFF |
| 휴대폰 탐지 불안정 | 랜덤 MAC 사용 중 | 휴대폰에서 기기 MAC 사용으로 변경 |
| Npcap 관련 오류 | Npcap 미설치 | Npcap 설치 후 재부팅 |

---

## 🔮 향후 개발 계획

- [ ] 수동 승인 모드 (팝업에서 바로 허용/차단)
- [ ] GUI 대시보드
- [ ] 기기 제조사 정보 표시 (MAC OUI 조회)
- [ ] 이메일 알림 연동
- [ ] 통계 및 리포트 기능

---

## 📄 라이선스

MIT License - 자유롭게 수정하고 사용하세요.
=======
# network-intrusion-detector
>>>>>>> cba012b4f91efd44ff1a95f31236a4ba3ec57ff9
