#!/bin/bash

# このスクリプトは、OpenSSL の `asn1parse` コマンドを使って
# X.509 証明書ファイル `sample.crt` の ASN.1 構造を解析・表示するためのものです。
#
# X.509 証明書は内部的には ASN.1 (Abstract Syntax Notation One) という
# データ構造記法で表現されており、通常は DER または PEM 形式で保存されます。
#
# `openssl x509 -text -noout -in sample.crt` は
# 「証明書の意味」を人間向けに要約して表示しますが、
#
# `openssl asn1parse -i -in sample.crt`
#
# はそれより低レイヤーで、
# 「証明書が ASN.1 としてどのような木構造でエンコードされているか」
# を表示します。
#
# つまり、このスクリプトは
#
#   証明書の意味を読む
#
# ではなく
#
#   証明書のバイナリ構造を読む
#
# ためのものです。
#
# SSL/TLS 学習の文脈では、次のような用途で役立ちます。
#
# - X.509 証明書の内部構造を理解する
# - Subject / Issuer / Validity / Public Key などが
#   ASN.1 のどこにあるか確認する
# - 拡張領域 (Extensions) の位置や構造を確認する
# - DER / PEM と ASN.1 の関係を理解する
#
# 注意:
# `asn1parse` の出力はかなり低レベルであり、
# 初見では読みにくいことが多いです。
# そのため、まずは `openssl x509 -text -noout -in sample.crt` と
# 対応づけながら読むのがおすすめです。


# エラー発生時にスクリプトを停止する設定です。
# -e : コマンドが失敗したら即終了
# -u : 未定義変数を使ったらエラー
# -o pipefail : パイプ中の失敗も検出
set -euo pipefail


# 入力となる証明書ファイルです。
# ここでは自己署名証明書や CA 署名証明書など、
# すでに作成済みの PEM 形式証明書を想定しています。
CERT_FILE="sample.crt"


# 入力証明書が存在するかを先に確認します。
# これをしておくと、OpenSSL 側のエラーよりも
# 原因を分かりやすく表示できます。
if [[ ! -f "${CERT_FILE}" ]]; then
  echo "[ERROR] 証明書ファイル ${CERT_FILE} が存在しません。"
  echo "[INFO] 先に sample.crt を生成してください。"
  exit 1
fi


# openssl asn1parse
# ASN.1 データ構造を解析して表示する OpenSSL コマンドです。
#
# -i
#   インデント付きで表示します。
#   ASN.1 の入れ子構造が見やすくなるため、
#   学習用途ではほぼ必須と考えてよいです。
#
# -in "${CERT_FILE}"
#   解析対象の入力ファイルを指定します。
#
# `sample.crt` が PEM 形式なら、OpenSSL が中身を読み取って
# Base64 デコードし、その内部の ASN.1 / DER 構造を解析します。
#
# 出力では、たとえば次のような情報が見えます。
#
# - d=0  hl=4 l=...
#   ルートの深さやヘッダ長、データ長
#
# - SEQUENCE
#   ASN.1 のシーケンス構造
#
# - INTEGER
#   バージョン番号やシリアル番号など
#
# - OBJECT
#   アルゴリズム識別子や属性 OID など
#
# - UTCTIME / GENERALIZEDTIME
#   証明書の有効期限
#
# つまり、このコマンドは証明書を
#
#   X.509 の意味構造
#
# ではなく
#
#   ASN.1 タグ / 長さ / 値
#
# の観点で分解して見せます。
#
# 証明書の概念的な構造は大まかに次のようになっています。
#
#   Certificate
#     ├─ tbsCertificate
#     │    ├─ version
#     │    ├─ serialNumber
#     │    ├─ signature
#     │    ├─ issuer
#     │    ├─ validity
#     │    ├─ subject
#     │    ├─ subjectPublicKeyInfo
#     │    └─ extensions
#     ├─ signatureAlgorithm
#     └─ signatureValue
#
# `asn1parse` は、この木構造をさらに ASN.1 レベルの
# SEQUENCE / SET / OBJECT / BIT STRING 等へ展開して表示します。
openssl asn1parse \
  -i \
  -in "${CERT_FILE}"


# 実行後に併用すると理解しやすい確認コマンド例:
#
# 1. 証明書の意味を人間向けに表示する
#    openssl x509 -in sample.crt -text -noout
#
# 2. Subject を確認する
#    openssl x509 -in sample.crt -noout -subject
#
# 3. Issuer を確認する
#    openssl x509 -in sample.crt -noout -issuer
#
# 4. 有効期限を確認する
#    openssl x509 -in sample.crt -noout -dates
#
# 学習のコツ:
# - まず `openssl x509 -text` で意味を読む
# - 次に `openssl asn1parse` で ASN.1 のどこに対応するかを見る
#
# という順にすると理解しやすいです。
#
# セキュリティ上の注意:
# - `sample.crt` は通常公開可能な証明書ファイルであり、
#   `sample.key` のような秘密鍵ではありません。
# - ただし、証明書には組織名・ホスト名・有効期限などの
#   メタデータが含まれるため、取り扱いには状況に応じた注意が必要です。
