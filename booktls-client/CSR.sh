#!/bin/bash

# このスクリプトは、既存の秘密鍵 sample.key を使って
# CSR (Certificate Signing Request) を生成する。
#
# 今回の環境では openssl version -d の結果が
#   OPENSSLDIR: "/opt/openssl/ssl"
# になっているため、OpenSSL は標準では
#   /opt/openssl/ssl/openssl.cnf
# を読もうとする。
#
# しかし、その場所に openssl.cnf が存在しないため、
# `openssl req` が失敗する。
#
# そのため、このスクリプトでは -config オプションを使って
# Ubuntu 側に存在する設定ファイル /etc/ssl/openssl.cnf を
# 明示的に指定する。

set -euo pipefail

# 入力となる秘密鍵ファイル
KEY_FILE="sample.key"

# 出力する CSR ファイル
CSR_FILE="sample.csr"

# 使用する OpenSSL 設定ファイル
OPENSSL_CNF="/etc/ssl/openssl.cnf"

# 秘密鍵ファイルが存在するか確認する
if [[ ! -f "${KEY_FILE}" ]]; then
  echo "[ERROR] 秘密鍵ファイル ${KEY_FILE} が存在しません。"
  exit 1
fi

# OpenSSL 設定ファイルが存在するか確認する
if [[ ! -f "${OPENSSL_CNF}" ]]; then
  echo "[ERROR] OpenSSL 設定ファイル ${OPENSSL_CNF} が存在しません。"
  exit 1
fi

# CSR を生成する
#
# -new
#   新しい CSR を作成する
#
# -config "${OPENSSL_CNF}"
#   使用する openssl.cnf を明示的に指定する
#
# -key "${KEY_FILE}"
#   CSR に対応する秘密鍵を指定する
#
# -out "${CSR_FILE}"
#   生成した CSR の出力先ファイルを指定する
openssl req \
  -new \
  -config "${OPENSSL_CNF}" \
  -key "${KEY_FILE}" \
  -out "${CSR_FILE}"

# 出力確認
if [[ -f "${CSR_FILE}" ]]; then
  echo "[INFO] CSR ファイル ${CSR_FILE} を生成しました。"
else
  echo "[ERROR] CSR ファイル ${CSR_FILE} の生成に失敗しました。"
  exit 1
fi
