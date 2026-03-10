#!/bin/bash

# このスクリプトは tshark を使って、
# すべてのネットワークインターフェースから
# TCP/UDP ポート 10443 の通信だけをキャプチャし、
# その内容を詳細表示して log に保存するためのものです。
#
# 今回は Docker 環境で TLS 通信を観察したいため、
# 特定の物理NICではなく `any` を使って
# 全インターフェースを対象にしています。
#
# 主な用途:
# - OpenSSL s_client で server に接続したときの TLS ハンドシェイク観察
# - Docker bridge / veth をまたぐ通信の確認
# - Wireshark GUI を使わずに CLI だけで TLS パケットを見る

# sudo
# パケットキャプチャには通常 root 権限が必要です。
#
# tshark
# Wireshark の CLI 版ツールです。
#
# -i any
# すべてのインターフェースを対象にキャプチャします。
# Docker 環境では enp0s3, br-xxxx, vethxxxx など複数あるため、
# 学習用途では `any` が最も手軽です。
#
# -f "port 10443"
# これはキャプチャフィルタです。
# port 10443 の通信だけを取得します。
# つまり不要な通信を最初から除外できます。
#
# -V
# パケットを詳細表示します。
# Ethernet / IP / TCP / TLS の各階層が展開されるため、
# TLS の ClientHello や ServerHello を確認しやすくなります。
#
# | tee log
# 標準出力を
# - 画面に表示
# - log ファイルに保存
# の両方で行います。
#
# 注意:
# `port 10443 -V` のように書くと、
# `-V` までフィルタ文字列として解釈されてエラーになります。
# そのため、`-V` はフィルタの前にオプションとして書くか、
# `-f "..."` を明示するのが安全です。

sudo tshark -i any -f "port 10443" -V | tee log
