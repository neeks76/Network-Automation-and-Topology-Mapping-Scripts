# 네트워크 자동화 및 토폴로지 매핑 스크립트

## 개요

이 스크립트는 Python으로 작성되었으며, Netmiko 라이브러리를 사용하여 네트워크 장비에 자동으로 연결하고 정보를 수집합니다. 수집된 정보를 바탕으로 Excel 보고서와 Draw.io에서 사용할 수 있는 네트워크 토폴로지 맵을 생성하여 네트워크 가시성을 높이고 문서화 작업을 자동화합니다.

## 주요 기능

- **자동 정보 수집**: Cisco IOS 및 NX-OS 장비에 SSH로 연결하여 CDP(Cisco Discovery Protocol) 및 LLDP(Link Layer Discovery Protocol) 이웃 정보를 수집합니다.
- **상세 정보 조회**: 각 인터페이스의 IP 주소, VLAN (Access/Trunk), Port-Channel 멤버 등 상세 정보를 파싱합니다.
- **재귀적 탐색**: 최초 장비 목록(`device_list.txt`)을 시작으로, 연결된 모든 이웃 장비를 재귀적으로 탐색하여 전체 네트워크 토폴로지 정보를 수집할 수 있습니다.
- **인터페이스 설명 자동 업데이트**: 수집된 이웃 장비 정보를 바탕으로 각 장비의 인터페이스에 "Connected to [이웃 장비명] - [이웃 인터페이스명]" 형식의 설명을 자동으로 설정하는 옵션을 제공합니다.
- **결과 보고서 생성**: 수집된 모든 연결 정보를 `cdp_neighbors_auto.xlsx` 파일로 저장하여 체계적으로 관리할 수 있습니다.
- **토폴로지 맵 생성**: Draw.io(app.diagrams.net)에서 바로 불러올 수 있는 `network_topology_filtered.xml` 파일을 생성하여 네트워크 다이어그램을 시각화합니다.

## 사전 준비 사항

### 1. Python 설치

스크립트를 실행하기 위해 Python 3가 설치되어 있어야 합니다.

### 2. 필요 라이브러리 설치

아래 명령어를 사용하여 스크립트 실행에 필요한 라이브러리를 설치합니다.

```bash
pip install pandas netmiko openpyxl
```

### 3. 장비 목록 파일 생성

스크립트와 동일한 디렉토리에 `device_list.txt` 파일을 생성하고, 스크립트가 처음 연결할 네트워크 장비의 IP 주소를 한 줄에 하나씩 입력합니다. `#`으로 시작하는 라인은 주석 처리되어 무시됩니다.

**device_list.txt 예시:**
```
# --- Core Switches ---
192.168.1.1
192.168.1.2

# --- Distribution Switches ---
192.168.10.1
```

## 사용 방법

1.  터미널 또는 명령 프롬프트에서 스크립트가 있는 디렉토리로 이동합니다.
2.  아래 명령어를 실행하여 스크립트를 시작합니다.
    ```bash
    python network-automation-and-topology-scripts2.0.py
    ```
3.  스크립트가 시작되면 아래와 같은 정보를 순서대로 입력합니다.
    - **Update interface descriptions? (y/n)**: 인터페이스 설명 자동 업데이트 기능 사용 여부.
    - **Automatically discover and process all neighbors recursively? (y/n)**: 재귀적 탐색 기능 사용 여부.
    - **Username**: 장비에 로그인할 사용자 이름.
    - **Password**: 로그인 암호.
    - **Enable password**: Enable 모드 진입 암호 (없으면 Enter).
4.  스크립트가 실행되면서 각 장비에 연결하고 정보 수집을 시작합니다. 콘솔에 진행 상황이 출력됩니다.

## 결과물

스크립트 실행이 완료되면 아래 파일들이 생성됩니다.

- **`cdp_neighbors_auto.xlsx`**: 수집된 모든 장비와 인터페이스 연결 정보가 정리된 Excel 파일. 각 행은 하나의 연결을 나타냅니다 (Hostname-A, Interface-A, Hostname-B, Interface-B 등).
- **`network_topology_filtered.xml`**: Draw.io(app.diagrams.net)에서 `File > Open from` 또는 `File > Import from` 메뉴를 통해 불러올 수 있는 XML 파일입니다. 네트워크 토폴로지를 시각적으로 확인할 수 있습니다.
- **`netmiko_debug.log`**: 스크립트 실행 과정에서 발생하는 상세 로그가 기록되는 파일. 문제 해결 시 유용합니다.
- **`netmiko_session.log`**: Netmiko 라이브러리의 SSH 세션 관련 로그가 기록되는 파일입니다.