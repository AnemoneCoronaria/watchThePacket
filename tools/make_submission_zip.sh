#!/usr/bin/env bash
# 3차 과제 제출용 zip 만들기 (과제 설명서: 소스 코드 + 빌드 관련 파일, 빌드/실행 중 생기는 파일은 제외)
#   tools/make_submission_zip.sh            -> 컴네-3차과제-2조-프로그램.zip
#   tools/make_submission_zip.sh 이름.zip    -> 원하는 이름으로
# git에 올라간 파일만 넣음 -> .venv, __pycache__, ui_main.py, res_rc.py, .pcap 같은 건 자동으로 빠짐
set -e
cd "$(dirname "$0")/.."
OUT="${1:-컴네-3차과제-2조-프로그램.zip}"

if [ -n "$(git status --porcelain)" ]; then
    echo "주의: 커밋 안 한 변경이 있어요. zip에는 지금 폴더의 파일 내용이 들어가요 (git에 등록된 파일만)."
fi
rm -f "$OUT"
git ls-files -z | xargs -0 zip -q "$OUT"
echo "만들었어요: $OUT ($(git ls-files | wc -l | tr -d ' ')개 파일)"
unzip -l "$OUT" | tail -1
