#!/usr/bin/env python3
"""
========================================
Network Intrusion Detection System
로컬 네트워크 침입 탐지 시스템 - 최종 완성본
========================================

[동작 방식]
1. 주기적으로 네트워크를 스캔 (세 가지 방법 병행)
   ① Windows ARP 캐시 읽기  - 이미 통신 중인 기기 탐지
   ② ARP 패킷 스캔          - 신규 연결 기기 탐지
   ③ ICMP ping 스캔         - 위 둘에서 놓친 기기 보완

2. 발견된 기기를 whitelist.json과 비교

3. 미등록 기기 발견 시 경보
   - CMD 경고 출력
   - Windows 데스크톱 알림
   - 로그 파일 기록
"""

import json
import time
import logging
import os
import sys
import socket
import struct
import subprocess
import re
import concurrent.futures
from datetime import datetime
from scapy.all import ARP, Ether, ICMP, IP, srp, sr1, conf
from winotify import Notification, audio

conf.verb = 0  # Scapy 경고 메시지 억제


class NetworkMonitor:
    def __init__(self, config_file='config.json', whitelist_file='whitelist.json'):
        """네트워크 모니터 초기화"""
        current_dir = os.getcwd()
        print(f"📁 현재 작업 디렉토리: {current_dir}")

        # 절대 경로로 파일 읽기 (관리자 권한 실행 시에도 올바른 경로 사용)
        config_path    = os.path.join(current_dir, config_file)
        whitelist_path = os.path.join(current_dir, whitelist_file)

        print(f"📄 설정 파일    : {config_path}")
        print(f"📄 화이트리스트 : {whitelist_path}")

        self.config         = self.load_config(config_path)
        self.whitelist      = self.load_whitelist(whitelist_path)
        self.whitelist_file = whitelist_path
        self.detected_devices = {}  # 이미 탐지된 기기 (중복 알림 방지)
        self.setup_logging()

    # ══════════════════════════════════════════
    # 설정 / 화이트리스트 관리
    # ══════════════════════════════════════════

    def load_config(self, config_file):
        """config.json 로드 - 없으면 기본값 사용"""
        try:
            if os.path.exists(config_file):
                with open(config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                print(f"✓ 설정 파일 로드 성공")
                print(f"  - IP 범위   : {config.get('ip_range', 'NOT SET')}")
                print(f"  - 스캔 주기 : {config.get('scan_interval', 'NOT SET')}초")
                return config
            else:
                print(f"⚠️  설정 파일 없음 → 기본값 사용")
                return self.get_default_config()
        except Exception as e:
            print(f"❌ 설정 파일 읽기 오류: {e}")
            return self.get_default_config()

    def get_default_config(self):
        """기본 설정값"""
        return {
            "scan_interval" : 30,       # 스캔 주기 (초)
            "ip_range"      : "192.168.1.0/24",  # 스캔할 IP 범위
            "log_file"      : "network_monitor.log",
            "enable_sound"  : False,    # 알림 소리 여부
            "arp_timeout"   : 3,        # ARP 응답 대기 시간 (초)
            "arp_retry"     : 2,        # ARP 재시도 횟수
            "use_icmp"      : True,     # ICMP 스캔 사용 여부
            "icmp_timeout"  : 1,        # ICMP 응답 대기 시간 (초)
            "icmp_workers"  : 50        # ICMP 병렬 처리 수
        }

    def load_whitelist(self, whitelist_file):
        """whitelist.json 로드 - 승인된 기기 목록"""
        try:
            if os.path.exists(whitelist_file):
                with open(whitelist_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                whitelist = {d['mac'].lower(): d for d in data['approved_devices']}
                print(f"✓ 화이트리스트 로드 성공: {len(whitelist)}개 기기")
                return whitelist
            else:
                print(f"⚠️  화이트리스트 없음 → 빈 목록으로 시작")
                return {}
        except Exception as e:
            print(f"❌ 화이트리스트 읽기 오류: {e}")
            return {}

    def save_whitelist(self):
        """화이트리스트를 whitelist.json에 저장"""
        try:
            data = {'approved_devices': list(self.whitelist.values())}
            with open(self.whitelist_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"❌ 화이트리스트 저장 실패: {e}")
            logging.error(f"화이트리스트 저장 오류: {e}")

    def add_to_whitelist(self, device, name="", description=""):
        """기기를 화이트리스트에 추가"""
        mac = device['mac'].lower()
        if mac not in self.whitelist:
            self.whitelist[mac] = {
                'mac'        : mac,
                'name'       : name or f"Device_{mac[-8:]}",
                'description': description,
                'added_date' : datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            self.save_whitelist()
            print(f"✅ 화이트리스트 추가: {mac} ({name})")
            logging.info(f"화이트리스트 추가: {mac}")
        else:
            print(f"ℹ️  이미 등록된 기기: {mac}")

    def check_device(self, device):
        """기기가 화이트리스트에 등록되어 있는지 확인"""
        return device['mac'].lower() in self.whitelist

    def setup_logging(self):
        """로그 파일 설정"""
        log_file = self.config.get('log_file', 'network_monitor.log')
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            encoding='utf-8'
        )
        print(f"✓ 로그 파일: {log_file}")

    # ══════════════════════════════════════════
    # 스캔 방법 1: Windows ARP 캐시 읽기
    # ══════════════════════════════════════════

    def read_arp_cache(self, ip_range):
        """
        'arp -a' 명령어로 Windows ARP 캐시를 직접 읽음.

        [원리]
        Windows는 네트워크 통신이 발생할 때마다
        IP ↔ MAC 주소 매핑을 자동으로 ARP 캐시에 기록함.
        이 캐시를 읽으면 패킷을 전송하지 않아도
        현재 통신 중인 모든 기기를 확인할 수 있음.

        [장점]
        - AP 격리, 방화벽의 영향을 받지 않음
        - 매우 빠름 (패킷 전송/응답 대기 없음)
        - arp -a 결과와 동일하게 모든 기기 탐지

        [한계]
        - 한 번도 통신한 적 없는 기기는 캐시에 없을 수 있음
        → ARP/ICMP 스캔으로 보완
        """
        print(f"  [1단계] Windows ARP 캐시 읽는 중...")

        try:
            result = subprocess.run(
                ['arp', '-a'],
                capture_output=True,
                text=True,
                encoding='cp949'  # Windows 한글 CMD 인코딩
            )
            output = result.stdout
        except Exception as e:
            print(f"  [ARP 캐시] 오류: {e}")
            return {}

        # IP 범위 파싱 (설정된 범위 외의 IP 제외)
        base_ip, prefix = ip_range.rsplit('/', 1)
        prefix    = int(prefix)
        base      = struct.unpack('>I', socket.inet_aton(base_ip))[0]
        mask      = ((1 << 32) - 1) ^ ((1 << (32 - prefix)) - 1)
        net_start = base & mask
        net_end   = net_start | (~mask & 0xFFFFFFFF)

        def in_range(ip_str):
            try:
                ip_int = struct.unpack('>I', socket.inet_aton(ip_str))[0]
                return net_start <= ip_int <= net_end
            except Exception:
                return False

        # arp -a 출력 파싱
        # 예: "  192.168.0.101    b8-27-eb-44-fc-09    동적"
        pattern = re.compile(
            r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+'
            r'([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}'
            r'[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})'
        )

        devices = {}
        for line in output.splitlines():
            match = pattern.search(line)
            if match:
                ip  = match.group(1)
                mac = match.group(2).replace('-', ':').lower()

                # 브로드캐스트·멀티캐스트 제외
                if mac in ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00'):
                    continue
                if mac.startswith(('01:', '33:', '03:')):
                    continue

                # 설정한 IP 범위 내 기기만 포함
                if in_range(ip):
                    devices[mac] = {'ip': ip, 'mac': mac}

        print(f"  [1단계] {len(devices)}개 기기 발견")
        return devices

    # ══════════════════════════════════════════
    # 스캔 방법 2: ARP 패킷 스캔
    # ══════════════════════════════════════════

    def arp_scan(self, ip_range):
        """
        ARP 패킷을 직접 전송해 응답하는 기기 탐지.

        [원리]
        네트워크 전체에 ARP 요청을 브로드캐스트 전송.
        응답한 기기의 IP와 MAC 주소를 수집.

        [장점]
        - 방금 연결된 신규 기기를 즉시 탐지
        - ARP 캐시에 아직 없는 기기도 탐지 가능

        [한계]
        - AP 격리 또는 방화벽이 켜진 기기는 탐지 어려움
        → ARP 캐시 읽기로 보완
        """
        timeout = self.config.get('arp_timeout', 3)
        retry   = self.config.get('arp_retry', 2)
        print(f"  [2단계] ARP 패킷 스캔 중 (timeout={timeout}s, retry={retry})")

        arp    = ARP(pdst=ip_range)
        ether  = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp

        try:
            answered, _ = srp(packet, timeout=timeout, retry=retry, verbose=0)
        except Exception as e:
            print(f"  [ARP 스캔] 오류: {e}")
            return {}

        devices = {}
        for _, received in answered:
            mac = received.hwsrc.lower()
            ip  = received.psrc
            devices[mac] = {'ip': ip, 'mac': mac}

        print(f"  [2단계] {len(devices)}개 기기 발견")
        return devices

    # ══════════════════════════════════════════
    # 스캔 방법 3: ICMP ping 스캔
    # ══════════════════════════════════════════

    def icmp_ping(self, ip):
        """단일 IP에 ICMP ping 전송 - 응답 시 IP 반환"""
        timeout = self.config.get('icmp_timeout', 1)
        try:
            pkt  = IP(dst=ip) / ICMP()
            resp = sr1(pkt, timeout=timeout, verbose=0)
            if resp is not None:
                return ip
        except Exception:
            pass
        return None

    def icmp_scan(self, ip_range):
        """
        IP 범위 전체에 병렬 ping 전송.

        [원리]
        네트워크 범위 내 모든 IP에 동시에 ping을 보냄.
        응답한 IP 목록 수집 후 MAC 주소를 추가로 조회.

        [장점]
        - ARP에 응답 안 하는 기기도 탐지 가능
        - 병렬 처리로 빠른 스캔

        [한계]
        - ICMP를 차단하는 기기는 탐지 불가
        - MAC 주소를 바로 알 수 없어 추가 조회 필요
        """
        workers = self.config.get('icmp_workers', 50)

        # IP 범위 내 모든 IP 주소 생성
        base_ip, prefix = ip_range.rsplit('/', 1)
        prefix = int(prefix)
        base   = struct.unpack('>I', socket.inet_aton(base_ip))[0]
        mask   = ((1 << 32) - 1) ^ ((1 << (32 - prefix)) - 1)
        start  = (base & mask) + 1
        end    = (base | ~mask & 0xFFFFFFFF) - 1

        all_ips = [
            socket.inet_ntoa(struct.pack('>I', i))
            for i in range(start, end + 1)
        ]

        print(f"  [3단계] ICMP ping {len(all_ips)}개 IP 병렬 스캔 중 (workers={workers})")

        active_ips = set()
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {executor.submit(self.icmp_ping, ip): ip for ip in all_ips}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    active_ips.add(result)

        print(f"  [3단계] {len(active_ips)}개 IP 응답")
        return active_ips

    def resolve_mac(self, ip):
        """ICMP로만 발견된 IP의 MAC 주소를 ARP로 재조회"""
        timeout = self.config.get('arp_timeout', 3)
        arp    = ARP(pdst=ip)
        ether  = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        try:
            answered, _ = srp(packet, timeout=timeout, retry=1, verbose=0)
            if answered:
                return answered[0][1].hwsrc.lower()
        except Exception:
            pass
        return 'unknown'

    # ══════════════════════════════════════════
    # 복합 스캔 (세 가지 방법 통합)
    # ══════════════════════════════════════════

    def scan_network(self, ip_range=None):
        """
        세 가지 스캔을 순서대로 실행하고 결과를 합산.

        [전체 흐름]
        1단계: ARP 캐시 읽기  → 통신 중인 기기 (AP격리·방화벽 무관)
        2단계: ARP 패킷 스캔  → 신규 연결 기기 보완
        3단계: ICMP ping 스캔 → 위 둘에서 놓친 기기 최종 보완
        → 세 결과를 합쳐서 최종 기기 목록 반환
        """
        if ip_range is None:
            ip_range = self.config.get('ip_range', '192.168.1.0/24')
            print(f"📝 IP 범위: {ip_range}")

        print(f"\n🔍 복합 스캔 시작... ({ip_range})")

        all_devices = {}

        try:
            # ── 1단계: ARP 캐시 (가장 신뢰도 높음) ──
            cache_devices = self.read_arp_cache(ip_range)
            all_devices.update(cache_devices)

            # ── 2단계: ARP 패킷 스캔 ──
            arp_devices = self.arp_scan(ip_range)
            for mac, device in arp_devices.items():
                if mac not in all_devices:
                    all_devices[mac] = device

            # ── 3단계: ICMP 스캔으로 최종 보완 ──
            use_icmp = self.config.get('use_icmp', True)
            if use_icmp:
                icmp_ips  = self.icmp_scan(ip_range)
                known_ips = {d['ip'] for d in all_devices.values()}
                new_ips   = icmp_ips - known_ips

                if new_ips:
                    print(f"  [보완] 미발견 IP {len(new_ips)}개 MAC 재조회 중...")
                    for ip in new_ips:
                        mac = self.resolve_mac(ip)
                        if mac not in all_devices:
                            all_devices[mac] = {'ip': ip, 'mac': mac}
                            print(f"    + {ip}  MAC={mac}")

            # ── 최종 결과 출력 ──
            devices = list(all_devices.values())
            print(f"\n✅ 스캔 완료: 총 {len(devices)}개 기기 발견")
            print(f"   (ARP캐시: {len(cache_devices)} | "
                  f"ARP스캔: {len(arp_devices)} | "
                  f"최종합산: {len(devices)})")
            return devices

        except PermissionError:
            print("❌ 관리자 권한이 필요합니다.")
            print("CMD를 관리자 권한으로 실행해주세요.")
            sys.exit(1)
        except Exception as e:
            print(f"❌ 스캔 오류: {e}")
            logging.error(f"스캔 오류: {e}")
            return []

    # ══════════════════════════════════════════
    # 경보 발송
    # ══════════════════════════════════════════

    def send_notification(self, device):
        """미인가 기기 발견 시 Windows 데스크톱 알림 전송"""
        mac = device['mac']
        ip  = device['ip']

        toast = Notification(
            app_id="Network Monitor",
            title="⚠️ 알 수 없는 기기 탐지!",
            msg=f"새로운 기기가 네트워크에 연결되었습니다.\n\nMAC: {mac}\nIP:  {ip}",
            duration="long",
            icon=None
        )
        if self.config.get('enable_sound', False):
            toast.set_audio(audio.Default, loop=False)
        toast.show()
        print(f"🔔 알림 발송: {mac} ({ip})")

    # ══════════════════════════════════════════
    # 메인 모니터링 루프
    # ══════════════════════════════════════════

    def monitor(self):
        """
        네트워크를 주기적으로 스캔하고 미인가 기기 발견 시 경보.

        [동작 순서]
        1. 네트워크 스캔 (3가지 방법 복합)
        2. 화이트리스트와 비교
        3. 미등록 기기 발견 시:
           - CMD 경고 출력
           - Windows 팝업 알림
           - 로그 파일 기록
        4. 설정된 주기만큼 대기 후 반복
        """
        print("\n" + "=" * 70)
        print("🛡️  네트워크 침입 탐지 시스템 시작")
        print("     (Windows ARP 캐시 + ARP 스캔 + ICMP 복합 방식)")
        print("=" * 70)

        ip_range      = self.config.get('ip_range', '192.168.1.0/24')
        scan_interval = self.config.get('scan_interval', 30)

        print(f"📋 화이트리스트 : {len(self.whitelist)}개 기기 등록됨")
        print(f"⏱️  스캔 주기    : {scan_interval}초")
        print(f"🌐 IP 범위      : {ip_range}")
        print(f"🔔 알림 소리    : {'켜짐' if self.config.get('enable_sound') else '꺼짐'}")
        print("=" * 70)
        print("\n모니터링 중... (Ctrl+C로 종료)\n")

        # 시작 시 ARP 캐시 갱신을 위한 브로드캐스트 ping
        print("🔄 초기 ARP 캐시 갱신 중...")
        try:
            broadcast = ip_range.rsplit('.', 1)[0] + '.255'
            subprocess.run(
                ['ping', '-n', '1', '-w', '1000', broadcast],
                capture_output=True
            )
        except Exception:
            pass

        try:
            while True:
                devices = self.scan_network()

                for device in devices:
                    mac = device['mac']
                    ip  = device['ip']

                    # 처음 발견된 기기인지 확인 (중복 알림 방지)
                    if mac not in self.detected_devices:
                        self.detected_devices[mac] = device

                        # 화이트리스트에 없는 미인가 기기
                        if not self.check_device(device):
                            print(f"\n{'='*50}")
                            print(f"⚠️  경고: 미인가 기기 탐지!")
                            print(f"   MAC  : {mac}")
                            print(f"   IP   : {ip}")
                            print(f"   시간 : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                            print(f"{'='*50}\n")

                            self.send_notification(device)
                            logging.warning(f"미인가 기기 탐지 - MAC: {mac}, IP: {ip}")

                print(f"[{datetime.now().strftime('%H:%M:%S')}] "
                      f"✓ {len(devices)}개 기기 발견 "
                      f"/ 화이트리스트: {len(self.whitelist)}개 "
                      f"/ 다음 스캔: {scan_interval}초 후")

                time.sleep(scan_interval)

        except KeyboardInterrupt:
            print("\n\n🛑 모니터링 종료")
            logging.info("모니터링 종료")

    # ══════════════════════════════════════════
    # 기기 목록 출력
    # ══════════════════════════════════════════

    def list_devices(self):
        """현재 네트워크에 연결된 모든 기기 목록 출력"""
        devices = self.scan_network()

        if not devices:
            print("\n❌ 기기를 찾을 수 없습니다.")
            print("\n💡 확인사항:")
            print("   1. config.json의 ip_range가 현재 네트워크와 일치하는지 확인")
            print("      (CMD에서 ipconfig 입력 후 IPv4 주소 확인)")
            print("   2. 관리자 권한으로 실행 중인지 확인")
            print("   3. Wi-Fi가 제대로 연결되어 있는지 확인")
            return

        print(f"\n현재 네트워크 기기 목록 ({len(devices)}개)")
        print("=" * 75)
        print(f"{'상태':<10} {'MAC 주소':<20} {'IP 주소':<16} {'이름':<20}")
        print("=" * 75)

        approved_count   = 0
        unapproved_count = 0

        for device in sorted(devices, key=lambda x: x['ip']):
            mac = device['mac']
            ip  = device['ip']

            if self.check_device(device):
                status = "✅ 승인됨"
                name   = self.whitelist[mac].get('name', 'N/A')
                approved_count += 1
            else:
                status = "⚠️  미승인"
                name   = "알 수 없음"
                unapproved_count += 1

            print(f"{status:<10} {mac:<20} {ip:<16} {name:<20}")

        print("=" * 75)
        print(f"승인됨: {approved_count}개 | 미승인: {unapproved_count}개\n")


# ══════════════════════════════════════════
# 메인 실행
# ══════════════════════════════════════════

def print_help():
    print("""
네트워크 침입 탐지 시스템 - 사용법
========================================

[명령어]
python network_monitor.py              - 모니터링 시작
python network_monitor.py list         - 현재 네트워크 기기 목록 확인
python network_monitor.py add <MAC> [이름] [설명]
                                       - 기기를 화이트리스트에 추가
python network_monitor.py help         - 도움말 표시

[예시]
python network_monitor.py add aa:bb:cc:dd:ee:ff "내 노트북" "개인용 노트북"
python network_monitor.py add 11:22:33:44:55:66 "내 휴대폰"

[추천 사용 순서]
1. python network_monitor.py list       → 현재 기기 목록 확인
2. python network_monitor.py add [MAC]  → 정상 기기 화이트리스트 등록
3. python network_monitor.py            → 모니터링 시작

[주의사항]
- 반드시 관리자 권한으로 실행하세요
- config.json의 ip_range를 현재 네트워크에 맞게 설정하세요
  (CMD에서 ipconfig 입력 후 IPv4 주소 확인)
    """)


def main():
    print("=" * 70)
    print("🛡️  Network Intrusion Detection System - Final Version")
    print("=" * 70 + "\n")

    monitor = NetworkMonitor()

    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == "list":
            monitor.list_devices()

        elif command == "add":
            if len(sys.argv) < 3:
                print("사용법: python network_monitor.py add <MAC주소> [이름] [설명]")
                print("예시  : python network_monitor.py add aa:bb:cc:dd:ee:ff \"내 노트북\"")
                return
            mac         = sys.argv[2].lower()
            name        = sys.argv[3] if len(sys.argv) > 3 else ""
            description = sys.argv[4] if len(sys.argv) > 4 else ""
            monitor.add_to_whitelist({'mac': mac, 'ip': 'N/A'}, name, description)

        elif command == "help":
            print_help()

        else:
            print(f"❌ 알 수 없는 명령어: '{command}'")
            print("python network_monitor.py help 로 사용법을 확인하세요.")
    else:
        monitor.monitor()


if __name__ == "__main__":
    main()
