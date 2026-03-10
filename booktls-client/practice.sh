#!/bin/bash

# このスクリプトは OpenSSL の `s_client` を使って、
# `booktls-server:10443` で待ち受けている TLS サーバへ接続し、
# サーバ証明書の検証を行いながらハンドシェイク情報を確認するためのものです。
#
# 典型的な用途:
# - TLS 1.2 で本当に接続できるか確認する
# - サーバ証明書が `ca.pem` によって検証できるか確認する
# - ハンドシェイク時にどの暗号スイートや証明書チェーンが使われたかを見る

# エラーが起きた時点で終了する設定です。
# -e : コマンドが失敗したら即終了
# -u : 未定義変数を使ったらエラー
# -o pipefail : パイプ途中の失敗も検出する
set -euo pipefail

# ログファイル名です。
LOG_FILE="log"

# 接続先ホスト名です。
# docker compose の同一ネットワーク上にいる server コンテナ
# `booktls-server` を名前解決して接続する想定です。
HOST="booktls-server"

# 接続先ポートです。
# 10443 は、この学習環境では HTTPS/TLS の検証用ポートとして使われています。
PORT="10443"

# 信頼する CA 証明書ファイルです。
# `s_client` は通常、公開サーバ向けのシステム CA ストアを使うこともありますが、
# 学習環境や自作 CA の場合は `-CAfile` で明示するのが重要です。
CA_FILE="ca.pem"

# まず、以降の標準出力と標準エラー出力をすべて log に保存するようにします。
# これにより、
# - 画面に表示される
# - 同時に log に追記される
# という動作になります。
#
# 元のコマンドでは `openssl ... | tee log` としていましたが、
# それだと標準エラー出力の内容が log に入らないことがあります。
# SSL/TLS のデバッグではエラーメッセージも重要なので、
# ここではスクリプト全体を log に流す形へ補完しています。
exec > >(tee -a "${LOG_FILE}") 2>&1

echo "===== openssl s_client による TLS 接続確認を開始 ====="
echo "[INFO] 接続先ホスト: ${HOST}"
echo "[INFO] 接続先ポート: ${PORT}"
echo "[INFO] CA ファイル: ${CA_FILE}"

# CA ファイルが存在するか確認します。
# 存在しないと証明書検証ができず、原因切り分けがしにくくなるため、
# 先に明示的にチェックします。
if [[ ! -f "${CA_FILE}" ]]; then
  echo "[ERROR] CA ファイル ${CA_FILE} が存在しません。"
  exit 1
fi

# OpenSSL の s_client で TLS 接続を行います。
#
# 各オプションの意味:
#
# -connect ${HOST}:${PORT}
#   接続先のホスト名とポート番号を指定します。
#   Docker Compose の同一ネットワーク上では、
#   サービス名や container_name で名前解決できることが多いです。
#
# -tls1_2
#   TLS 1.2 で接続を強制します。
#   これにより、TLS 1.3 が有効なサーバでも、あえて TLS 1.2 での挙動を確認できます。
#
# -CAfile "${CA_FILE}"
#   サーバ証明書を検証するための CA 証明書ファイルを指定します。
#   自前 CA で署名した証明書を使う学習環境では非常に重要です。
#
# 補足:
# `openssl s_client` は単に接続するだけでなく、
# - サーバ証明書
# - 証明書チェーン
# - 使用プロトコル
# - 使用暗号スイート
# - Verify return code
# などを表示してくれるため、TLS 学習で頻繁に使われます。
openssl s_client \
  -connect "${HOST}:${PORT}" \
  -tls1_2 \
  -CAfile "${CA_FILE}"

echo "===== openssl s_client による TLS 接続確認を終了 ====="
