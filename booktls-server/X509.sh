#!/bin/bash

# このスクリプトは、server コンテナ内に配置されている
# X.509 サーバ証明書 `server.crt` の内容を人間が読める形式で表示し、
# その結果を log に保存するためのものです。
#
# 今回の重要な前提:
# - `server.crt` はカレントディレクトリには無い
# - 以前の Dockerfile では次のように証明書を配置している
#
#     COPY certs/server.crt /etc/nginx/certs/server.crt
#
# したがって、server コンテナ内での実際の配置先は
#
#     /etc/nginx/certs/server.crt
#
# です。
#
# そのため、この修正版では CERT_FILE を
# `/etc/nginx/certs/server.crt` に変更しています。
#
# 注意:
# - このスクリプトは server コンテナ内で実行する想定です。
# - client コンテナ内で実行すると、そのパスにファイルが無い可能性があります。
# - client 側で見たい場合は、/share へコピーしてから読む方法が分かりやすいです。


# エラーが発生した時点でスクリプトを停止する設定です。
# -e : いずれかのコマンドが失敗したら終了
# -u : 未定義変数を使ったらエラー
# -o pipefail : パイプライン内の失敗も検出
set -euo pipefail


# 解析対象となる証明書ファイルです。
# Dockerfile の COPY 先に合わせて、server コンテナ内の実パスを指定します。
CERT_FILE="/etc/nginx/certs/server.crt"

# 画面表示と同時に保存するログファイル名です。
LOG_FILE="log"


# 入力ファイルが存在するかを確認します。
# 存在しない場合は OpenSSL 側のエラーに任せるのではなく、
# どのパスを見に行ったのか分かる形で明示的に終了します。
if [[ ! -f "${CERT_FILE}" ]]; then
  echo "[ERROR] 証明書ファイル ${CERT_FILE} が存在しません。"
  echo "[INFO] このスクリプトは server コンテナ内で実行する想定です。"
  echo "[INFO] 先に次のコマンドで存在確認してください:"
  echo "       ls -l ${CERT_FILE}"
  exit 1
fi


# openssl x509
# X.509 証明書を表示・変換・検査するための OpenSSL コマンドです。
#
# -in "${CERT_FILE}"
#   入力ファイルとして /etc/nginx/certs/server.crt を指定します。
#   OpenSSL はこのファイルを証明書として読み込みます。
#
# -text
#   証明書の内容を人間が読める形式で表示します。
#   具体的には、証明書内部の各フィールドを整形して出力します。
#
# 元のコマンドでは `-noout` が付いていないため、
# `-text` による説明表示に加えて PEM 本文も出力されます。
# 学習用途では、説明表示と元の証明書本文の両方を見られるため有益です。
#
# | tee "${LOG_FILE}"
#   標準出力を
#   - 画面に表示
#   - log ファイルに保存
#   の両方で行います。
#
# このコマンドで主に確認できる項目:
# - Version
# - Serial Number
# - Signature Algorithm
# - Issuer
# - Validity
# - Subject
# - Subject Public Key Info
# - X509v3 extensions
# - Signature Value
#
# 証明書の概念構造:
#
#   server.crt
#       ↓
#   X.509 Certificate
#       ├─ 発行者 (Issuer)
#       ├─ 所有者 (Subject)
#       ├─ 有効期限 (Validity)
#       ├─ 公開鍵 (Public Key)
#       ├─ 拡張 (Extensions)
#       └─ 署名 (Signature)
openssl x509 \
  -in "${CERT_FILE}" \
  -text \
  | tee "${LOG_FILE}"


# 実務・学習でよく併用する確認コマンド例:
#
# 1. PEM 本文を出さず、説明だけ見たい
#    openssl x509 -in /etc/nginx/certs/server.crt -text -noout
#
# 2. Subject だけ見たい
#    openssl x509 -in /etc/nginx/certs/server.crt -noout -subject
#
# 3. Issuer だけ見たい
#    openssl x509 -in /etc/nginx/certs/server.crt -noout -issuer
#
# 4. 有効期限だけ見たい
#    openssl x509 -in /etc/nginx/certs/server.crt -noout -dates
#
# 5. フィンガープリントを見たい
#    openssl x509 -in /etc/nginx/certs/server.crt -noout -fingerprint -sha256
#
# 6. SAN を確認したい
#    openssl x509 -in /etc/nginx/certs/server.crt -text -noout | grep -A 1 "Subject Alternative Name"
#
# 7. server 証明書を共有ディレクトリへコピーして client 側から見たい
#    cp /etc/nginx/certs/server.crt /share/server.crt
#
# セキュリティ上の注意:
# - `server.crt` は通常公開可能な証明書ファイルであり、
#   `server.key` のような秘密鍵ではありません。
# - ただし、証明書にはホスト名・組織名・有効期限などの情報が含まれるため、
#   ログや画面出力を共有する際は用途に応じて注意が必要です。
