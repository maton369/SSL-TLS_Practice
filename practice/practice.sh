// 注意:
// - このスクリプトは「鍵」と「IV（初期化ベクタ）」まで log に出力する。
// - 学習用途としては分かりやすいが、実運用では秘密鍵素材をログへ残すのは非常に危険である。
// - 実運用では、鍵や IV をログに残さない・安全な保管領域を使う・アクセス制御を行う、が原則である。

#!/bin/bash

# エラーが起きた時点で即終了する。
# -e : いずれかのコマンドが失敗したら終了
# -u : 未定義変数を使ったらエラー
# -o pipefail : パイプ途中の失敗も検知する
set -euo pipefail

# ログファイル名を定義する。
LOG_FILE="log"

# このスクリプト以降の「標準出力」と「標準エラー出力」を
# すべて tee 経由で log に追記する。
# これにより、画面にも表示され、同時に log にも残る。
exec > >(tee -a "${LOG_FILE}") 2>&1

echo "===== ChaCha20 暗号化処理を開始 ====="

# 入力ファイルを定義する。
# 平文データ（暗号化前のメッセージ）が入っている想定である。
INPUT_FILE="message.txt"

# 出力ファイルを定義する。
# ChaCha20 で暗号化されたバイナリを保存する。
OUTPUT_FILE="chacha20.bin"

# 入力ファイルの存在確認を行う。
# 存在しない場合は、そのまま openssl を実行すると失敗するため、
# 先に明示的に検査してエラー終了する。
if [[ ! -f "${INPUT_FILE}" ]]; then
  echo "[ERROR] 入力ファイル ${INPUT_FILE} が存在しません。"
  exit 1
fi

# ChaCha20 用の鍵を生成する。
# `openssl rand -hex 32` は 32 バイト = 256 bit の乱数を 16進文字列で出力する。
# ChaCha20 は 256 bit 鍵を使うため、この長さが適切である。
#
# 例:
# 32 バイトの乱数
# ↓
# 16進文字列では 64 文字になる
KEY_HEX="$(openssl rand -hex 32)"

# ChaCha20 用の IV（初期化ベクタ）を生成する。
# OpenSSL の chacha20 実装では 128 bit = 16 バイトの IV を渡す形式で使う。
# そのため `-hex 16` ではなく、16 バイト分の 16 進表現として
# `openssl rand -hex 16` を使う。
#
# 16 バイト = 128 bit
# 16進文字列では 32 文字になる。
IV_HEX="$(openssl rand -hex 16)"

echo "[INFO] 入力ファイル: ${INPUT_FILE}"
echo "[INFO] 出力ファイル: ${OUTPUT_FILE}"

# 学習用として鍵と IV をログへ出力する。
# ただし、これは実運用では非常に危険である。
# 秘密情報がログに残ると、ログを見た第三者が復号できてしまう。
echo "[INFO] 生成した鍵 (256 bit / hex): ${KEY_HEX}"
echo "[INFO] 生成したIV (128 bit / hex): ${IV_HEX}"

# ChaCha20 で平文を暗号化する。
#
# 各オプションの意味:
# enc         : OpenSSL の対称暗号コマンドを使う
# -chacha20   : アルゴリズムとして ChaCha20 を指定する
# -e          : encrypt（暗号化）を意味する
# -K          : 鍵を 16進文字列で直接指定する
# -iv         : IV を 16進文字列で直接指定する
# -in         : 入力ファイルを指定する
# -out        : 出力ファイルを指定する
#
#
# 注意:
# `openssl chacha20` ではなく、一般的には `openssl enc -chacha20` と書く。
# OpenSSL のバージョンやビルドによっては前者が動かないことがあるため、
# 互換性の観点から `enc -chacha20` 形式を用いる。
openssl enc -chacha20 \
  -e \
  -K "${KEY_HEX}" \
  -iv "${IV_HEX}" \
  -in "${INPUT_FILE}" \
  -out "${OUTPUT_FILE}"

echo "[INFO] 暗号化が完了しました。"

# 出力ファイルの存在確認を行う。
if [[ -f "${OUTPUT_FILE}" ]]; then
  echo "[INFO] 出力ファイル ${OUTPUT_FILE} の作成を確認しました。"
else
  echo "[ERROR] 出力ファイル ${OUTPUT_FILE} が作成されていません。"
  exit 1
fi

# ファイルサイズもログに残しておく。
# 暗号化処理後に最低限の確認情報として有用である。
wc -c "${INPUT_FILE}" "${OUTPUT_FILE}"

echo "===== ChaCha20 暗号化処理を終了 ====="
