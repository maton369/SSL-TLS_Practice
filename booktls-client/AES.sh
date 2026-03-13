#!/bin/bash

# ============================================================
# OpenSSL 暗号性能ベンチマークスクリプト
# ============================================================
#
# このスクリプトは OpenSSL の `speed` コマンドを使って、
# 次の暗号方式の性能を測定する。
#
#   1. AES-128-GCM
#   2. AES-256-GCM
#   3. ChaCha20-Poly1305
#
# さらに、それぞれについて
#
#   - AES-NI を有効にした通常状態
#   - AES-NI を無効化した状態
#
# の両方を測定する。
#
# ------------------------------------------------------------
# このスクリプトで比較したいこと
# ------------------------------------------------------------
#
# AES-GCM は CPU が AES-NI を持っている場合、
# ハードウェア支援によって大きく高速化されることが多い。
#
# 一方で ChaCha20-Poly1305 は AES-NI の有無による影響を受けにくく、
# 特に AES 命令支援が弱い環境では有力な選択肢になる。
#
# そのため、次の比較がこのスクリプトの主目的である。
#
#   通常状態:
#     AES-GCM はどれくらい速いか
#
#   AES-NI 無効時:
#     AES-GCM の性能はどの程度落ちるか
#     ChaCha20-Poly1305 と比べてどうなるか
#
# ------------------------------------------------------------
# アルゴリズムの流れ
# ------------------------------------------------------------
#
# このスクリプト全体の処理は次の順序で進む。
#
#   1. ログ保存先ディレクトリを作成する
#   2. 通常状態で各アルゴリズムを測定する
#   3. AES-NI 無効状態で各アルゴリズムを測定する
#   4. それぞれの結果を対応するログファイルへ保存する
#
# 図にすると次のようになる。
#
#   通常状態
#     ├─ aes-128-gcm benchmark  → log
#     ├─ aes-256-gcm benchmark  → log
#     └─ chacha20-poly1305      → log
#
#   AES-NI 無効状態
#     ├─ aes-128-gcm benchmark  → log
#     ├─ aes-256-gcm benchmark  → log
#     └─ chacha20-poly1305      → log
#
# ------------------------------------------------------------
# 入力コマンドに対する補完・修正点
# ------------------------------------------------------------
#
# 元の断片には以下の問題があったため、このスクリプトでは補完・修正している。
#
# 1. `-epapsed` は typo であり、正しくは `-elapsed`
#
# 2. `chacha20-poly` は OpenSSL の EVP 名として不完全であり、
#    一般的には `chacha20-poly1305` を使う
#
# 3. `OPENSSL_ia32cap="~0x200000200000000" openssl`
#    の行が途中で終わっていたため、
#    AES-NI 無効化を各 `openssl speed` コマンドに対して適用する形へ補完した
#
# ------------------------------------------------------------
# ログの扱い
# ------------------------------------------------------------
#
# 実行結果はそれぞれ対応するログファイルへ保存する。
#
# 例:
#   logs/aes128gcm_default.log
#   logs/aes256gcm_default.log
#   logs/chacha20poly1305_default.log
#   logs/aes128gcm_no_aesni.log
#   logs/aes256gcm_no_aesni.log
#   logs/chacha20poly1305_no_aesni.log
#
# 標準出力だけでなく標準エラーもログへ残すため、
# OpenSSL の出力を `tee` 経由で保存している。
#
# ------------------------------------------------------------
# AES-NI 無効化について
# ------------------------------------------------------------
#
# `OPENSSL_ia32cap="~0x200000200000000"` は、
# OpenSSL に対して x86 CPU capability の一部をマスクし、
# AES-NI などのハードウェア支援機能を見えなくするための環境変数設定として
# よく使われる。
#
# これにより、OpenSSL は AES-NI を使わないコードパスで暗号処理を行う。
#
# 注意:
# - この方法は OpenSSL と CPU アーキテクチャに依存する
# - x86/x86_64 向けの手法であり、ARM 環境では同じ意味にならない
# - OpenSSL のバージョンによっては挙動が微妙に異なる可能性がある


# エラー時に即停止する設定。
# -e : コマンド失敗時に終了
# -u : 未定義変数使用時に終了
# -o pipefail : パイプライン中の失敗も検知
set -euo pipefail


# ログ出力先ディレクトリ。
LOG_DIR="logs"

# ベンチマーク時間（秒）。
# OpenSSL speed に渡す -seconds の値として使う。
BENCH_SECONDS=10

# ログディレクトリが無ければ作成する。
mkdir -p "${LOG_DIR}"


# ------------------------------------------------------------
# run_bench:
#   OpenSSL speed コマンドを実行し、結果をログへ保存する補助関数
#
# 引数:
#   $1 : ログファイルパス
#   $2以降 : 実行するコマンド本体
#
# 役割:
#   - 何を測るかを画面とログの両方に分かりやすく出す
#   - 実際のベンチマーク結果を対応するログファイルへ保存する
#   - 標準エラーもログへ含める
# ------------------------------------------------------------
run_bench() {
  local logfile="$1"
  shift

  {
    echo "============================================================"
    echo "Benchmark started: $(date)"
    echo "Log file: ${logfile}"
    echo "Command: $*"
    echo "============================================================"
    "$@"
    echo
    echo "============================================================"
    echo "Benchmark finished: $(date)"
    echo "============================================================"
  } 2>&1 | tee "${logfile}"
}


# ============================================================
# 1. 通常状態でのベンチマーク
# ============================================================

# AES-128-GCM の通常状態ベンチマーク。
# -elapsed
#   CPU 時間ではなく実時間ベースで測定する。
#   コンテナや仮想環境でも直感的に解釈しやすい。
#
# -evp aes-128-gcm
#   EVP インターフェース経由で AES-128-GCM を測定する。
#
# -seconds "${BENCH_SECONDS}"
#   指定秒数だけベンチマークを回す。
run_bench \
  "${LOG_DIR}/aes128gcm_default.log" \
  openssl speed -elapsed -evp aes-128-gcm -seconds "${BENCH_SECONDS}"


# AES-256-GCM の通常状態ベンチマーク。
run_bench \
  "${LOG_DIR}/aes256gcm_default.log" \
  openssl speed -elapsed -evp aes-256-gcm -seconds "${BENCH_SECONDS}"


# ChaCha20-Poly1305 の通常状態ベンチマーク。
#
# 元の入力では `chacha20-poly` となっていたが、
# OpenSSL の EVP 名としては `chacha20-poly1305` を使うのが自然なので補完している。
run_bench \
  "${LOG_DIR}/chacha20poly1305_default.log" \
  openssl speed -elapsed -evp chacha20-poly1305 -seconds "${BENCH_SECONDS}"


# ============================================================
# 2. AES-NI を無効にした状態でのベンチマーク
# ============================================================

# AES-NI 無効時の AES-128-GCM ベンチマーク。
#
# OPENSSL_ia32cap="~0x200000200000000"
#   OpenSSL に対して CPU capability の一部を隠し、
#   AES-NI を使わない経路へ誘導する。
run_bench \
  "${LOG_DIR}/aes128gcm_no_aesni.log" \
  env OPENSSL_ia32cap="~0x200000200000000" \
  openssl speed -elapsed -evp aes-128-gcm -seconds "${BENCH_SECONDS}"


# AES-NI 無効時の AES-256-GCM ベンチマーク。
run_bench \
  "${LOG_DIR}/aes256gcm_no_aesni.log" \
  env OPENSSL_ia32cap="~0x200000200000000" \
  openssl speed -elapsed -evp aes-256-gcm -seconds "${BENCH_SECONDS}"


# AES-NI 無効時の ChaCha20-Poly1305 ベンチマーク。
#
# ChaCha20-Poly1305 自体は AES-NI を直接使うアルゴリズムではないため、
# ここでは「AES 系が弱くなった環境での比較対象」として測定している。
run_bench \
  "${LOG_DIR}/chacha20poly1305_no_aesni.log" \
  env OPENSSL_ia32cap="~0x200000200000000" \
  openssl speed -elapsed -evp chacha20-poly1305 -seconds "${BENCH_SECONDS}"


# ============================================================
# 3. 実行結果の保存先一覧を表示
# ============================================================
#
# 最後に、どのファイルに何が保存されたかを一覧表示する。
# ログ解析や比較のときに見返しやすくするためである。
echo
echo "Benchmark logs saved to:"
echo "  ${LOG_DIR}/aes128gcm_default.log"
echo "  ${LOG_DIR}/aes256gcm_default.log"
echo "  ${LOG_DIR}/chacha20poly1305_default.log"
echo "  ${LOG_DIR}/aes128gcm_no_aesni.log"
echo "  ${LOG_DIR}/aes256gcm_no_aesni.log"
echo "  ${LOG_DIR}/chacha20poly1305_no_aesni.log"
